#include "RangeManager.h"
#include "Connection.h"
#include "ByteRange.h"
#include "analyseTCP.h"
#include "color_print.h"
#include "util.h"
#include <memory>

map<const long, int> GlobStats::byteLatencyVariationCDFValues;

const char *received_type_str[] = {"DEF", "DTA", "RDB", "RTR"};

RangeManager::~RangeManager() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	for (; it != it_end; it++) {
		delete it->second;
	}
}

/*
  If relative_seq option is enabled, the seq argument is returned as is.
  If disabled, it will convert the seq to the absolute sequence number (the actual value found in the TCP header)
 */
ulong RangeManager::relative_seq(ulong seq) {
	if (GlobOpts::relative_seq)
		return seq;
	ulong wrap_index;
	wrap_index = (firstSeq + seq) / 4294967296L;
	//	printf("relative_seq: seq: %lu, first + seq: %lu, wrap_index: %lu\n", seq, firstSeq + seq, wrap_index);
	ulong res = seq + firstSeq;
	res -= ((ulong) wrap_index * 4294967296L);
	//printf("relative_seq  ret: %lu\n", res);
	return res;
}


/* Register all bytes with a common send time as a range */
void RangeManager::insertSentRange(struct sendData *sd) {
	static ulong startSeq;
	static ulong endSeq;
	startSeq = sd->data.seq;
	endSeq = sd->data.endSeq;

#ifdef DEBUG
	int debug_print = 0;
	if (debug_print) {
		printf("\ninsertSentRange (%lu): (%lu - %lu) (%lu - %lu), retrans: %d, is_rdb: %d\n", endSeq == startSeq ? 0 : endSeq - startSeq +1,
			   relative_seq(startSeq), relative_seq(endSeq), startSeq, endSeq, sd->data.retrans, sd->data.is_rdb);
	}
#endif
	insert_byte_range(startSeq, endSeq, true, &(sd->data), 0);

	if (sd->data.payloadSize == 0) { /* First or second packet in stream */
#ifdef DEBUG
		if (debug_print)
			printf("-------Creating first range---------\n");
#endif
		if (!(sd->data.flags & TH_RST)) {
			lastSeq = endSeq;
			if (sd->data.flags & TH_SYN)
				lastSeq += 1;
		}
	}
	else if (startSeq == lastSeq) { /* Next packet in correct sequence */
#ifdef DEBUG
		if (debug_print) {
			printf("-------New range equivalent with packet---------\n");
			printf("%s - inserted Range with startseq: %lu\n", conn->getConnKey().c_str(), relative_seq(startSeq));
		}
#endif
		lastSeq = startSeq + sd->data.payloadSize;
	}
	/* Check for instances where sent packets are lost from the packet trace */
	else if (startSeq > lastSeq) {
		// This is most probably the ack on the FIN ack from receiver, so ignore
		if (sd->data.payloadSize != 0) {
			printf("RangeManager::insertRange: Missing byte in send range in conn '%s''\n", conn->getConnKey().c_str());
			printf("Expected seq: %lu but got %lu\n", lastSeq, startSeq);
			printf("Absolute: lastSeq: %lu, startSeq: %lu. Relative: lastSeq: %lu, startSeq: %lu\n",
				   lastSeq, startSeq, relative_seq(lastSeq), relative_seq(startSeq));
			printf("This is an indication that tcpdump has dropped packets while collecting the trace.\n");
			warn_with_file_and_linenum(__FILE__, __LINE__);
		}
	}
	else if (startSeq > lastSeq) {

		// This is an ack
		if (sd->data.payloadSize == 0) {
			lastSeq = startSeq + sd->data.payloadSize;
		}
		else {
			lastSeq = startSeq + sd->data.payloadSize;
#ifdef DEBUG
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->data.payloadSize);
			}
#endif
		}
	}
	else if (startSeq < lastSeq) { /* We have some kind of overlap */

		if (endSeq <= lastSeq) {/* All bytes are already registered: Retransmission */
#ifdef DEBUG
			if (debug_print)
				printf("-------All bytes have already been registered - discarding---------");
#endif
			redundantBytes += (endSeq +1 - startSeq);
#ifdef DEBUG
			if (debug_print) {
				printf("Adding %lu redundant bytes to connection\n", (endSeq +1 - startSeq));
			}
#endif
		} else { /* Old and new bytes: Bundle */
#ifdef DEBUG
			if (debug_print)
				printf("-------Overlap: registering some bytes---------");

			if ((endSeq - startSeq +1) != sd->data.payloadSize) {
				printf("Data len incorrect!\n");
				exit_with_file_and_linenum(1, __FILE__, __LINE__);
			}
#endif
			lastSeq = startSeq + sd->data.payloadSize;
#ifdef DEBUG
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->data.payloadSize);
			}
#endif
		}
	}
}

void RangeManager::insertReceivedRange(struct sendData *sd) {

	DataSeg tmpSeg;

	tmpSeg.seq = sd->data.seq;
	tmpSeg.endSeq = sd->data.endSeq;
	tmpSeg.tstamp_pcap = (sd->data.tstamp_pcap);
	//tmpSeg.data = sd->data.data;
	tmpSeg.payloadSize = sd->data.payloadSize;
	tmpSeg.is_rdb = sd->data.is_rdb;
	tmpSeg.retrans = sd->data.retrans;
	tmpSeg.tstamp_tcp = sd->data.tstamp_tcp;
	tmpSeg.window = sd->data.window;
	tmpSeg.flags = sd->data.flags;

	if (tmpSeg.payloadSize > 0)
		tmpSeg.endSeq -= 1;

	if (GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5) {
		cerr << "Inserting receive data: startSeq=" << relative_seq(tmpSeg.seq) << ", endSeq=" << relative_seq(tmpSeg.endSeq) << endl;
		if (tmpSeg.seq == 0 || tmpSeg.endSeq == 0) {
			cerr << "Erroneous seq." << endl;
		}
	}
	/* Insert all packets into data structure */
	insert_byte_range(tmpSeg.seq, tmpSeg.endSeq, false, &tmpSeg, 0);
}

/*
  This inserts the the data into the ranges map.
  It's called both with sent end received data ranges.
*/
void RangeManager::insert_byte_range(ulong start_seq, ulong end_seq, bool sent, DataSeg *data_seg, int level) {
	ByteRange *last_br = NULL;
	map<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt_end = ranges.end();
	brIt = brIt_end;


#ifdef DEBUG
	int debug_print = 0;//GlobOpts::debugLevel == 6;
	if (TV_TO_MS(data_seg->tstamp_pcap) == 1396710194676) {
		printf("\n\nHEEEEEEI sent:%d level:%d\n\n", sent, level);
		printf("%s\n", conn->getConnKey().c_str());
		debug_print = 1;
	}
	//debug_print = 1;


	if (start_seq < 500) {
		debug_print = 1;
	}
	//if (start_seq >= 21643733)
	//	debug_print = 1;
	//
	//if (start_seq >= 21660765)
	//	exit(0);

	//if (start_seq >= 801 && start_seq <= 1101)
	//	debug_print = 1;
	//fprintf(stderr, "level: %d\n", level);

	char prefix[100];
	int i;
	int indent = level * 3;
	for (i = 0; i < indent; i++) {
		prefix[i] = ' ';
	}
	sprintf(prefix + indent, "%d", level);

#define indent_print(format, args...) printf("%s "format, prefix, args)
#define indent_print2(format) printf("%s "format, prefix)
#endif

	bool this_is_rdb_data = data_seg->is_rdb && data_seg->rdb_end_seq > start_seq;

#ifdef DEBUG
	if (debug_print) {
		if (!level)
			printf("\n");
		indent_print("insert_byte_range1 (%lu): (%lu - %lu) (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d, SYN: %d, FIN: %d, RST: %d\n", end_seq == start_seq ? 0 : end_seq - start_seq +1,
					 relative_seq(start_seq), relative_seq(end_seq), start_seq, end_seq, sent, data_seg->retrans, data_seg->is_rdb,
					 !!(data_seg->flags & TH_SYN), !!(data_seg->flags & TH_FIN), !!(data_seg->flags & TH_RST));
	}
#endif

	// An ack
	if (start_seq == end_seq) {

		if (sent) {
			analysed_sent_pure_ack_count++;
		}

		//If not SYN or FIN, it's pure ack (or RST)
		if (!(data_seg->flags & TH_SYN) && !(data_seg->flags & TH_FIN) && !(data_seg->flags & TH_RST)) {
			// If start seq -1 exists, use that
			if (ranges.find(start_seq -1) != brIt_end) {
				start_seq -= 1;
				end_seq = start_seq;
			}
#ifdef DEBUG
			/*
			if (debug_print) {
				if (!level)
					printf("\n");
				indent_print("insert_byte_range2 (%lu): (%lu - %lu) (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq == start_seq ? 0 : end_seq - start_seq +1,
							 relative_seq(start_seq), relative_seq(end_seq), start_seq, end_seq, sent, data_seg->retrans, data_seg->is_rdb);
			}
			*/
			if (debug_print) {
				indent_print("Pure ack! Decrease SEQ with 1: %lu\n", start_seq);
			}
#endif
		}
	}

	brIt = ranges.find(start_seq);

	// Doesn't exist
	if (brIt == brIt_end) {
#ifdef DEBUG
		if (debug_print) {
			indent_print("NOT FOUND: sent:%d, %lu - %lu (%lu)\n", sent, relative_seq(start_seq), relative_seq(end_seq), end_seq - start_seq + 1);
		}
#endif
		if (!sent) {
#ifdef DEBUG
			indent_print("Received non-existent byte range (%lu): (%lu - %lu) (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq == start_seq ? 0 : end_seq - start_seq +1,
						 relative_seq(start_seq), relative_seq(end_seq), start_seq, end_seq, sent, data_seg->retrans, data_seg->is_rdb);
			indent_print("Connection: %s\n", conn->getConnKey().c_str());
#endif
			warn_with_file_and_linenum(__FILE__, __LINE__);
		}

#ifdef DEBUG
		if (debug_print) {
			indent_print("Adding: %lu - %lu (start_seq: %lu)\n", relative_seq(start_seq), relative_seq(end_seq), start_seq);
		}
#endif
		// Ack / syn-ack /rst
		if (end_seq == start_seq) {
#ifdef DEBUG
			if (!sent) {
				//assert(0 && "RECEIVED!");
				colored_printf(RED, "Received packet with no payload\n");
			}
#endif

#ifdef DEBUG
			if (debug_print) {
				indent_print2("Create range with 0 len\n");
			}
#endif

			last_br = new ByteRange(start_seq, end_seq);
			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
			last_br->packet_retrans_count += data_seg->retrans;
			last_br->rdb_count += data_seg->is_rdb;
			if (data_seg->flags & TH_SYN) {
				//				printf("SYN 1\n");
				last_br->syn = 1;
#ifdef DEBUG
				if (debug_print) {
					indent_print2("Set SYN\n");
				}
#endif
			}
			else if (data_seg->flags & TH_FIN) {
				last_br->fin = 1;
#ifdef DEBUG
				if (debug_print) {
					indent_print2("Set FIN\n");
				}
#endif
			}
			else if (data_seg->flags & TH_RST) {
				last_br->rst = 1;
#ifdef DEBUG
				if (debug_print) {
					indent_print2("Set RST\n");
				}
#endif
			}
			else {
				last_br->acked_sent++;
				//last_br->packet_sent_count--;
			}
			ranges.insert(pair<ulong, ByteRange*>(start_seq, last_br));
			return;
		}

		map<ulong, ByteRange*>::iterator lowIt, highIt;
		highIt = ranges.upper_bound(end_seq);
		ulong new_end_seq = end_seq;

		// This is retransmitted or packet containing rdb data
		if (start_seq < lastSeq) {
#ifdef DEBUG
			// Some Non-rdb packets are registered as RDB because of segmentation-offloading
			if (debug_print) {
				indent_print("FOUND RETRANS: start_seq < lastSeq: %lu < %lu\n", start_seq, lastSeq);
			}
#endif
			ulong lower = std::min(0UL, start_seq - 30000);
			lowIt = ranges.lower_bound(lower);

			// Search for existing ranges for this data
			for (; lowIt != highIt && lowIt != highIt;) {

				// Found existing range
				// The existing range is bigger than the data to be registered, so we split the existing range
				if (lowIt->second->startSeq <= start_seq && lowIt->second->endSeq >= start_seq) {
#ifdef DEBUG
					if (lowIt->second->startSeq == start_seq) {
						printf("New Data is at the beginning of existing range!!\n");
						printf("Existing Range: %lu - %lu\n", relative_seq(lowIt->second->startSeq), relative_seq(lowIt->second->endSeq));
						printf("New data Range: %lu - %lu\n", relative_seq(start_seq), relative_seq(end_seq));
					}
					//assert(lowIt->second->startSeq != start_seq && "New Data is at beginning of existing range!!\n");
#endif
					// Splitting existing range
					ByteRange *cur_br = lowIt->second;
					int start_matches = (start_seq == cur_br->startSeq);
					int end_matches = (end_seq == cur_br->endSeq);
					int insert_more_recursively = 0;

					assert(!(start_matches && end_matches) && "BOTH");
#ifdef DEBUG
					if (debug_print) {
						indent_print("SENT: %d, rdb: %d, retrans: %d\n", sent, data_seg->is_rdb, data_seg->retrans);
						indent_print("Found existing range with matching data\n            for: %lu - %lu!\n", relative_seq(start_seq), relative_seq(end_seq));
						indent_print("Old Range        : %lu - %lu (%lu)\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq),
									 (cur_br->endSeq - cur_br->startSeq) +1);
					}
#endif
					ByteRange *range_received;
					ByteRange *new_br;
					if (start_matches) {
						new_br = cur_br->split_end(end_seq + 1, cur_br->endSeq);
						cur_br->packet_sent_count++;
						if (data_seg->flags & TH_FIN) {
							cur_br->fin += 1;
						}
#ifdef DEBUG
						if (debug_print) {
							indent_print("New Range 1      : %lu - %lu (%lu)\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
							indent_print("New Range 2      : %lu - %lu (%lu)\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
						}
#endif
						range_received = cur_br;
					}
					else if (end_matches) {
						new_br = cur_br->split_end(start_seq, cur_br->endSeq);
						new_br->packet_sent_count++;
						if (data_seg->flags & TH_FIN) {
							new_br->fin = 1;
						}
#ifdef DEBUG
						if (debug_print) {
							indent_print("New Range 1      : %lu - %lu (%lu)\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
							indent_print("New Range 2      : %lu - %lu (%lu)\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
						}
#endif
						range_received = new_br;
					}
					// New data fits into current range
					else if (end_seq < cur_br->endSeq) {
						// Split in the middle
						new_br = cur_br->split_end(start_seq, cur_br->endSeq);
						new_br->packet_sent_count++;
						if (data_seg->flags & TH_FIN) {
							new_br->fin = 1;
						}
						ByteRange *new_last = new_br->split_end(end_seq +1, new_br->endSeq);
#ifdef DEBUG
						if (debug_print) {
							indent_print("New Range 1      : %lu - %lu (%lu)\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
							indent_print("New Range 2      : %lu - %lu (%lu)\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
							indent_print("New Range 3      : %lu - %lu (%lu)\n", relative_seq(new_last->startSeq), relative_seq(new_last->endSeq), (new_last->endSeq - new_last->startSeq) +1);
						}
#endif
						ranges.insert(pair<ulong, ByteRange*>(new_last->startSeq, new_last));
						range_received = new_br;
					}
					// New data reaches beyond current range
					else {
						new_br = cur_br->split_end(start_seq, cur_br->endSeq);
						new_br->packet_sent_count++;
						range_received = new_br;
						insert_more_recursively = 1;
					}
					ranges.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));

					if (sent) {
						range_received->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
						if (!level)
							range_received->packet_retrans_count++;
						range_received->data_retrans_count++;

						//printf("data_seg->retrans: %d\n", data_seg->retrans);
						//fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
						assert("Retrans?" && data_seg->retrans != 0);
						//cur_br->retrans_count += data_seg->retrans;
						range_received->rdb_count += data_seg->is_rdb;
#ifdef DEBUG
						assert(!(!this_is_rdb_data && data_seg->is_rdb) && "Should not rdb data!\n");

						if (this_is_rdb_data) {
							assert(data_seg->retrans == 0 && "Should not be retrans!\n");
						}
						else {
							// Must this be retrans ?
							assert(data_seg->retrans != 0 && "Should be retransmission!\n");
						}
#endif
					}
					else {
						range_received->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					}

					if (insert_more_recursively) {
						//printf("Calling recursively: %lu - %lu\n", new_br->endSeq +1, end_seq);
						insert_byte_range(new_br->endSeq +1, end_seq, sent, data_seg, level +1);
					}
					return;
				}
				else
					lowIt++;
			}
		}

		if (sent) {
#ifdef DEBUG
			if (debug_print) {
				indent_print("data_seg->is_rdb: %d, this_is_rdb_data: %d\n", data_seg->is_rdb, this_is_rdb_data);
				indent_print("data_seg->rdb_end_seq > start_seq: %lu > %lu: %d\n", relative_seq(data_seg->rdb_end_seq), relative_seq(start_seq), data_seg->rdb_end_seq > start_seq);
			}
#endif
			last_br = new ByteRange(start_seq, new_end_seq);
			//printf("ByteRange size: %lu\n", sizeof(*last_br));

			last_br->original_payload_size = data_seg->payloadSize;
			if (data_seg->is_rdb) {
				last_br->original_packet_is_rdb = true;
				// Packet sent is already counted on previous range
				last_br->packet_sent_count = 0;
			}

			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
			if (data_seg->flags & TH_SYN) {
				assert("SYN" && 0);
				last_br->syn = 1;
			}
			else if (data_seg->flags & TH_FIN) {
				last_br->fin = 1;
			}
#ifdef DEBUG
			assert(data_seg->retrans == 0 && "Shouldn't be retrans!\n");
			assert(this_is_rdb_data == 0 && "Shouldn't be RDB?!\n");

			if ((new_end_seq - start_seq) > 100) {
				if (debug_print) {
					indent_print("Inserting new big range: %lu\n", (new_end_seq - start_seq +1));
					indent_print("original_payload_size: %d\n", last_br->original_payload_size);
				}
			}
#endif
			ranges.insert(pair<ulong, ByteRange*>(start_seq, last_br));
		}
#ifdef DEBUG
		else {
			// This data is only in the receiver dump
			if (start_seq > lastSeq) {
				last_br = new ByteRange(start_seq, end_seq);
				last_br->original_payload_size = data_seg->payloadSize;
				last_br->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);

				//last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
				if (data_seg->flags & TH_SYN) {
					last_br->syn = 1;
				}
				else if (data_seg->flags & TH_FIN) {
					last_br->fin = 1;
				}
#ifdef DEBUG
				assert(data_seg->retrans == 0 && "Shouldn't be retrans!\n");
				assert(this_is_rdb_data == 0 && "Shouldn't be RDB?!\n");
#endif
				ranges.insert(pair<ulong, ByteRange*>(start_seq, last_br));
			}
			//assert(sent && "RECEIVED??\n");
		}
#endif
	}
	// Exists in map
	else {
#ifdef DEBUG
		if (debug_print) {
			indent_print("FOUND START: sent:%d, %lu - %lu (%lu)\n", sent, relative_seq(start_seq), relative_seq(end_seq), end_seq - start_seq + 1);
			indent_print("Current startseq: %lu, endseq: %lu, new endseq: %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), relative_seq(end_seq));

			if (brIt->second->endSeq < brIt->second->startSeq) {
				colored_printf(RED, "Startseq is greater than Endseq!!\n");
			}
		}
#endif
		// No payload, so it's a syn or syn-ack (or fin, or rst)
		if (end_seq == start_seq) {
			brIt = ranges.find(start_seq);
			if (brIt != brIt_end) {
#ifdef DEBUG
				if (debug_print) {
					indent_print("Register SYN/SYN-ACK or FIN/FIN-ACK on '%s'\n", sent ? "sent" : "received");
					indent_print("SYN: %d, FIN: %d, ACK: %d\n", (data_seg->flags & TH_SYN) == TH_SYN, (data_seg->flags & TH_FIN) == TH_FIN, (data_seg->flags & TH_ACK) == TH_ACK);
				}
#endif
				if (sent) {
					brIt->second->packet_sent_count++;
					if (data_seg->flags & TH_SYN || data_seg->flags & TH_FIN) {
						//assert("Exists no payload " && 0);
						//colored_printf(RED, "SYN: %d, FIN: %d\n", !!(data_seg->flags & TH_SYN), data_seg->flags & TH_FIN);
						brIt->second->syn += !!(data_seg->flags & TH_SYN);
						brIt->second->fin += !!(data_seg->flags & TH_FIN);
						brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
						brIt->second->packet_retrans_count += 1;
					}
					else if (data_seg->flags & TH_RST) {
						brIt->second->rst++;
					}
					else {
						brIt->second->acked_sent += 1;
#ifdef DEBUG
						if (debug_print) {
							indent_print("Neither SYN nor FIN!, increased acked_sent to %d\n", brIt->second->acked_sent);
						}
#endif
					}
				}
				else {
					/*
					indent_print("insert_byte_range (%lu): (%lu - %lu) (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq == start_seq ? 0 : end_seq - start_seq +1,
								 relative_seq(start_seq), relative_seq(end_seq), start_seq, end_seq, sent, data_seg->retrans, data_seg->is_rdb);

					indent_print("FOUND RECEIVER SYN: sent:%d, %lu - %lu (%lu)\n", sent, relative_seq(start_seq), relative_seq(end_seq), end_seq - start_seq + 1);
					*/
					// Set receied tstamp for SYN/FIN
					if (data_seg->flags & TH_SYN || data_seg->flags & TH_FIN) {
						brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					}
				}
			}
#ifdef DEBUG
			else {
				printf("WAS END, searched for start: %lu\n", std::min(start_seq -1, start_seq));
			}
#endif
			return;
		}

		// The end_seq of the new range doesn't correspond to the end-seq of the entry in the map
		if (brIt->second->endSeq != end_seq) {

			if (!sent) {
				// The ack on the syn-ack
				if (end_seq == firstSeq +1) {
					brIt = ranges.find(start_seq -1);
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					assert(0 && "The ack on the syn-ack??\n");
					return;
				}
			}

			// Reaches multiple byte ranges
			if (brIt->second->endSeq < end_seq) {
#ifdef DEBUG
				if (debug_print) {
					indent_print("Overlaps multiple byte ranges: %lu - %lu\n", relative_seq(start_seq), relative_seq(end_seq));
					indent_print("Increase count of %lu - %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq));
					indent_print("Setting is_rdb : %d\n", data_seg->is_rdb);
					indent_print("Setting retrans: %d\n", data_seg->retrans);
				}
#endif
				if (sent) {
					assert("sent_count is 0!" && brIt->second->sent_count > 0);

					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);

					if (!level) {
						brIt->second->packet_retrans_count += data_seg->retrans;
						brIt->second->packet_sent_count++;
						if (data_seg->flags & TH_FIN) {
							brIt->second->fin += 1;
						}
					}
					brIt->second->data_retrans_count += data_seg->retrans;
					brIt->second->rdb_count += data_seg->is_rdb;

#ifdef DEBUG
					if (debug_print) {
						indent_print("Adding tcp timestamp 2 to %s : %u\n",  this_is_rdb_data ? "rdb" : "reg", data_seg->tstamp_tcp);
					}

					if (this_is_rdb_data) {
						assert(data_seg->retrans == 0 && "Should not be retrans!\n");
					}
#endif
				}
				else {
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					assert(brIt->second->received_tstamp_tcp && "TEST\n");
				}

				assert(level < 15 && "Recurse level too high");

				// Recursive call to insert the remaining data
				//printf("Recursive call: brIt->endseq: %lu, endseq: %lu\n", brIt->second->endSeq, end_seq);
				insert_byte_range(brIt->second->endSeq +1, end_seq, sent, data_seg, level +1);
			}
			// Reaches less than the range, split current range
			else {
				ByteRange *new_br = brIt->second->split_end(end_seq +1, brIt->second->endSeq);
#ifdef DEBUG
				if (debug_print) {
					indent_print2("Reaches less, split existing Range\n");
					indent_print("Existing range : %lu - %lu -> %lu - %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq),
								 relative_seq(brIt->second->startSeq), relative_seq(end_seq));
					indent_print("New range      : %lu - %lu\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq));
				}
#endif
				if (sent) {
					if (!level) {
						brIt->second->packet_retrans_count += data_seg->retrans;
						brIt->second->packet_sent_count++;
						if (data_seg->flags & TH_FIN) {
							brIt->second->fin += 1;
						}
					}
					brIt->second->data_retrans_count += data_seg->retrans;
					brIt->second->rdb_count += data_seg->is_rdb;
					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
#ifdef DEBUG
					if (this_is_rdb_data) {
						assert(data_seg->retrans != 0 && "Should not be retrans!\n");
					}
#endif
				}
				else {
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
				}
				ranges.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
			}
		}
		else {
			// The end_seq of the new range correspond to the end-seq of the entry in the map, so it's a duplicate
			if (sent) {
				brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
				if (!level) {
					brIt->second->packet_retrans_count += data_seg->retrans;
					brIt->second->packet_sent_count++;
					if (data_seg->flags & TH_FIN) {
						brIt->second->fin += 1;
					}
				}
				brIt->second->data_retrans_count += data_seg->retrans;
				brIt->second->rdb_count += data_seg->is_rdb;

				if (data_seg->flags & TH_SYN)
					brIt->second->syn += 1;
#ifdef DEBUG
				if (this_is_rdb_data) {
					assert(data_seg->retrans == 0 && "Should not be retrans!\n");
					if (debug_print) {
						indent_print("Adding tcp timestamp 3 to rdb : %u\n", data_seg->tstamp_tcp);
					}
				}
				else {
					if (debug_print) {
						indent_print("Adding tcp timestamp 4 to reg : %u\n", data_seg->tstamp_tcp);
					}
				}
#endif
			}
			else {
				brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
#ifdef DEBUG
				if (debug_print) {
					printf("Setting received timestamp: %u\n", brIt->second->received_tstamp_tcp);
					printf("tstamps: %lu, rdb-stamps: %lu", brIt->second->tstamps_tcp.size(), brIt->second->rdb_tstamps_tcp.size());
				}
#endif
			}
		}
	}
}


/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAck(struct DataSeg *seg) {
	static ByteRange* tmpRange;
	static bool ret;
	static ulong ack;
	int debug_print = 0;
	static map<ulong, ByteRange*>::iterator it, it_end, prev;
	ret = false;
	it = ranges.begin();
	it_end = ranges.end();
	ack = seg->ack;
	ack_count++;

	if (highestAckedByteRangeIt == ranges.end()) {
		it = ranges.begin();
	}
	else {
		it = highestAckedByteRangeIt;
	}

	if (debug_print) {
		printf("ProcessACK: %8lu  (%8lu), TSVal: %u, last acked start seq: %lu\n", relative_seq(ack), ack, seg->tstamp_tcp,
		       relative_seq(it->second->getStartSeq()));
	}

	/* All data from this ack has been acked before: return */
	if (ack <= it->second->getStartSeq()) {
		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "--------All data has been ACKed before - skipping--------" << endl;
		return true;
	}

	for (; it != it_end; it++) {
		tmpRange = it->second;

		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "tmpRange - startSeq: " << relative_seq(tmpRange->getStartSeq())
			     << " - endSeq: " << relative_seq(tmpRange->getEndSeq()) << endl;

		/* This ack covers this range, but not more: ack and return */
		if (ack == (tmpRange->getEndSeq() + 1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack equivalent with last range --------" << endl;
			if (debug_print)
				printf("  Covers just this Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));

			if (!tmpRange->isAcked()) {
				tmpRange->insertAckTime(&seg->tstamp_pcap);
				tmpRange->tcp_window = seg->window;
			}
			else {
				if (it == highestAckedByteRangeIt) {
					if (seg->window > 0 && seg->window == it->second->tcp_window) {
						it->second->dupack_count++;
					}
					else {
						it->second->tcp_window = seg->window;
					}
				}
			}
			it->second->ack_count++;
			highestAckedByteRangeIt = it;
			it->second->tcp_window = seg->window;
			return true;
		}

		/* ACK covers more than this range: ACK this range and continue */
		if (ack > (tmpRange->getEndSeq() +1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack covers more than this range: Continue to next --------" << endl;
			if (debug_print)
				printf("  Covers more than Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));


			if (timercmp(&seg->tstamp_pcap, &(tmpRange->sent_tstamp_pcap[0]), <)) {
				printf("ACK TIME IS EARLIER THAN SEND TIME!\n");
				return false;
			}

			if (!tmpRange->isAcked()) {
				tmpRange->insertAckTime(&seg->tstamp_pcap);
				ret = true;
			}
			highestAckedByteRangeIt = it;
			continue;
		}

		/* ACK covers only part of this range: split range and return */
		if (ack > tmpRange->getStartSeq() && ack < (tmpRange->getEndSeq() +1)) {
			if (debug_print) {
				printf("  Covers parts of  Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));
			}
			ByteRange *new_br = tmpRange->split_end(ack, tmpRange->endSeq);
			tmpRange->insertAckTime(&seg->tstamp_pcap);
			tmpRange->tcp_window = seg->window;
			tmpRange->ack_count++;

			// Second part of range: insert after tmpRange (tmpRange)
			highestAckedByteRangeIt = ranges.insert(std::pair<ulong, ByteRange*>(new_br->getStartSeq(), new_br)).first;
			return true;
		}

		// This is when receiver sends a FIN, the ack seq is then not incremented
		if ((seg->flags & TH_FIN) && ack == (tmpRange->getEndSeq())) {
			tmpRange->ack_count++;
			highestAckedByteRangeIt = it;
			return true;
		}
		prev = it;
		prev--;
		// ACK incremented one extra after receiving FIN
		if ((ack-2) == prev->second->getEndSeq()) {
			// There is a gap of 1 byte
			// This can be caused by a FIN being sent, and the seq num being increased
			// Even if no data was sent
			do {
				if (prev->second->fin) {
					prev->second->ack_count++;
					return true;
				}
				if (prev->second->packet_sent_count == prev->second->sent_count)
					break;
				prev--;
			} while (true);
		}

		/* If we get here, something's gone wrong */
		fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
		fprintf(stderr, "RangeManager::processAck: Possible error when processing ack: %lu (%lu)\n", relative_seq(ack), ack);
		fprintf(stderr, "Range(%lu, %lu) (%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()), tmpRange->getStartSeq(), tmpRange->getEndSeq());
		printf("tmpRange FIN: %d\n", prev->second->fin);
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}
	if (!ret)
		printf("ByteRange - Failed to find packet for ack: %lu\n", ack);

	return ret;
}


double median(vector<double>::const_iterator begin,
              vector<double>::const_iterator end) {
    int len = end - begin;
    if (len == 0)
	    return 0;
    vector<double>::const_iterator it = begin + (len / 2);
    double m = *it;
    if ((len % 2) == 0)
	    m = (m + *(--it)) / 2;
    return m;
}

void percentiles(const vector<double> *v, Percentiles *p) {
	map<string, double>::iterator it;
	double num;
	for (it = p->percentiles.begin(); it != p->percentiles.end(); it++) {
		istringstream(it->first) >> num;
		vector<double>::const_iterator it_p = v->begin() + ((int) ceil(v->size() * (num / 100.0)));
		it->second = *it_p;
	}
}

void RangeManager::genStats(struct byteStats *bs) {
	int latency;
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	int tmp_byte_count = 0;
	bs->minLat = bs->minLength = (numeric_limits<int>::max)();
	int dupack_count;

	for (; it != it_end; it++) {
		// Skip if invalid (negative) latency
		tmp_byte_count = it->second->getOrinalPayloadSize();
		bs->payload_lengths.push_back(tmp_byte_count);
		bs->cumLength += tmp_byte_count;
		for (int i = 0; i < it->second->getNumRetrans(); i++) {
			bs->payload_lengths.push_back(tmp_byte_count);
			bs->cumLength += tmp_byte_count;
		}

		dupack_count = it->second->dupack_count;

		// Make sure the vector has enough space
		for (int i = (int) bs->dupacks.size(); i < dupack_count; i++) {
			bs->dupacks.push_back(0);
		}

		for (int i = 0; i < dupack_count; i++) {
			bs->dupacks[i]++;
		}

		if (tmp_byte_count) {
			if (tmp_byte_count > bs->maxLength)
				bs->maxLength = tmp_byte_count;
			if (tmp_byte_count < bs->minLength) {
				bs->minLength = tmp_byte_count;
			}
		}

		if ((latency = it->second->getSendAckTimeDiff(this))) {
			bs->latencies.push_back(latency);
			bs->cumLat += latency;
			if (latency > bs->maxLat) {
				bs->maxLat = latency;
			}
			if (latency < bs->minLat) {
				bs->minLat = latency;
			}
			bs->nrRanges++;
		} else {
			if (!it->second->isAcked())
				continue;
		}

		int retrans = it->second->getNumRetrans();
		// Make sure the vector has enough space
		for (int i = bs->retrans.size(); i < retrans; i++) {
			bs->retrans.push_back(0);
		}
		for (int i = 0; i < retrans; i++) {
			bs->retrans[i]++;
		}
	}

	double temp;
	double stdev;
	if (bs->latencies.size()) {
		double sumLat = bs->cumLat;
		double mean =  sumLat / bs->latencies.size();
		temp = 0;

		for (unsigned int i = 0; i < bs->latencies.size(); i++) {
			temp += (bs->latencies[i] - mean) * (bs->latencies[i] - mean);
		}

		std::sort(bs->latencies.begin(), bs->latencies.end());

		stdev = sqrt(temp / (bs->latencies.size()));
		bs->stdevLat = stdev;
		percentiles(&bs->latencies, &bs->percentiles_latencies);
	}
	else
		bs->minLat = 0;

	if (bs->payload_lengths.size()) {
		// Payload size stats
		double sumLen = analysed_bytes_sent;
		double meanLen =  sumLen / bs->payload_lengths.size();
		bs->avgLength = meanLen;
		temp = 0;
		for (unsigned int i = 0; i < bs->payload_lengths.size(); i++) {
			temp += (bs->payload_lengths[i] - meanLen) * (bs->payload_lengths[i] - meanLen);
		}

		std::sort(bs->payload_lengths.begin(), bs->payload_lengths.end());
		stdev = sqrt(temp / (bs->payload_lengths.size()));
		bs->stdevLength = stdev;
		percentiles(&bs->payload_lengths, &bs->percentiles_lengths);
	}
	else
		bs->minLength = 0;
}

/* Check that every byte from firstSeq to lastSeq is present.
   Print number of ranges.
   Print number of sent bytes (payload).
   State if send-times occur: how many.
   State if ack-times occur: how many. */
void RangeManager::validateContent() {
	int numAckTimes = 0;
	int numSendTimes = 0;
	ulong tmpEndSeq = 0;

	map<ulong, ByteRange*>::iterator first, it, it_end, prev;
	first = it = ranges.begin();
	it_end = ranges.end();
	prev = it_end;

	/* FirstRange.startSeq == firstSeq
	   LastRange.endSeq == lastSeq
	   every packet in between are aligned */
	if (it->second->getStartSeq() != 0) {
		printf("firstSeq: %u, StartSeq: %lu\n", firstSeq, it->second->getStartSeq());
		printf("RangeManager::validateContent: firstSeq != StartSeq (%lu != %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(firstSeq));
		printf("First range (%lu, %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getEndSeq()));
		printf("Conn: %s\n", conn->getConnKey().c_str());
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	//printf("ranges.rbegin()->second->getEndSeq(): %lu\n", ranges.rbegin()->second->getEndSeq());
	//printf("lastSeq: %lu\n", lastSeq);
	//printf("ranges.rbegin()->second->getEndSeq(): %lu\n", ranges.rbegin()->second->getEndSeq());
	//printf("lastSeq - 1: %lu\n", lastSeq - 1);
	if (!(ranges.rbegin()->second->getEndSeq() <= lastSeq && ranges.rbegin()->second->getEndSeq() >= (lastSeq - 1))) {
		printf("RangeManager::validateContent: lastSeq unaligned! lastSeq: %lu, EndSeq: %lu\n", relative_seq(lastSeq), relative_seq(ranges.rbegin()->second->getEndSeq()));
		printf("Conn: %s\n", conn->getConnKey().c_str());
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	if (conn->totBytesSent != (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent)) {
		printf("conn->totBytesSent(%lu) does not equal (totNewDataSent + totRDBBytesSent + totRetransBytesSent) (%lu)\n",
		       conn->totBytesSent, (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent));
		printf("Conn: %s\n", conn->getConnKey().c_str());
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	for (it = ranges.begin(); it != it_end; it++) {

		// First element
		if (it == first) {
			tmpEndSeq = it->second->getEndSeq();
			continue;
		}

#ifdef DEBUG
		if (prev != it_end) {
			if (prev->second->endSeq +1 != it->second->startSeq && prev->second->startSeq != prev->second->endSeq) {
				// Allow gap at the end with FIN packets
				if (!prev->second->fin && it->second->byte_count) {
					printf("Range not continuous!\n Gap in %lu:%lu - %lu:%lu\n", prev->second->startSeq, prev->second->endSeq, it->second->startSeq, it->second->endSeq);
					printf("Conn: %s\n", conn->getConnKey().c_str());
				}
			}
		}
#endif

		// They are equal when previous has no payload
		if (it->second->getStartSeq() == tmpEndSeq +1) {
			tmpEndSeq = it->second->getEndSeq();
		} else {
			// ACKS
			if (prev == it_end || prev->second->getNumBytes() == 0 || it->second->getNumBytes() == 0) {
				tmpEndSeq = it->second->getEndSeq();
			}
			else {
				printf("PREV NUMBYTES: %d\n", prev->second->getNumBytes());
				printf("CURR NUMBYTES: %d\n", it->second->getNumBytes());

				cerr << "RangeManager::validateContent: Byte-stream in ranges not continuous. Exiting." << endl;
				printf("payload_len: %d\n", it->second->getNumBytes());

				printf("Prev Range (%lu, %lu) Len: %u\n", relative_seq(prev->second->getStartSeq()),
				       relative_seq(prev->second->getEndSeq()), prev->second->getNumBytes());
				printf("Curr Range (%lu, %lu) Len: %u\n", relative_seq(it->second->getStartSeq()),
				       relative_seq(it->second->getEndSeq()), it->second->getNumBytes());
				cerr << "tmpEndSeq           : " << relative_seq(tmpEndSeq) << endl;
				cerr << "Conn KEY           : " << conn->getConnKey() << endl;
				warn_with_file_and_linenum(__FILE__, __LINE__);
			}
		}

		if (it->second->getSendTime())
			numSendTimes++;
		if (it->second->getAckTime())
			numAckTimes++;

		prev = it;
	}

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "First seq: " << firstSeq << " Last seq: " <<  lastSeq << endl;
		cerr << "Number of ranges: " << ranges.size() << endl;
		cerr << "Number of bytes: " << lastSeq - firstSeq << endl;
		cerr << "numSendTimes: " << numSendTimes << endl;
		cerr << "numAckTimes: " << numAckTimes << endl;
		cerr << "Is first range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Is last range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Last range: startSeq: " << relative_seq(ranges.begin()->second->getStartSeq())
			 << " - endSeq: " << relative_seq(ranges.begin()->second->getEndSeq()) << endl;
	}
}


/*
  Print a list of all the registered ranges.
*/
void RangeManager::printPacketDetails() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	int seq_char_len = SSTR(relative_seq(ranges.rbegin()->second->endSeq)).length();

	cout << endl << "Packet details for conn: " << conn->getConnKey() << endl;

	for (; it != it_end; it++) {
		printf("Range (%4lu, %4d):", it->second->endSeq == it->second->startSeq ? 0 : it->second->endSeq - it->second->startSeq +1,
			   it->second->original_payload_size);

		printf(" %-*lu - %-*lu: snt-pkt: %d, sent: %d, rcv: %d, retr-pkt: %d, retr-dta: %d, rdb-cnt: %d, RCV: %s, rdb-miss: %-3d rdb-hit: %-3d",
		       seq_char_len, relative_seq(it->second->startSeq),
			   seq_char_len, relative_seq(it->second->endSeq), it->second->packet_sent_count,
			   it->second->sent_count, it->second->received_count, it->second->packet_retrans_count,
			   it->second->data_retrans_count, it->second->rdb_count, received_type_str[it->second->recv_type],
			   it->second->rdb_byte_miss, it->second->rdb_byte_hits);
		printf(" ACKtime: %4d ", it->second->getSendAckTimeDiff(this));
		printf(" RecvDiff: %4ld ", (it->second->getRecvDiff() - lowestRecvDiff));

		if (GlobOpts::verbose) {
			printf(" (%4ld) ", it->second->getSendAckTimeDiff(this) - (it->second->getRecvDiff() - lowestRecvDiff));
		}

		if (it->second->syn || it->second->rst || it->second->fin) {
			if (it->second->syn)
				colored_printf(YELLOW, "SYN(%d) ", it->second->syn);
			if (it->second->rst)
				colored_printf(YELLOW, "RST(%d) ", it->second->rst);
			if (it->second->fin)
				colored_printf(YELLOW, "FIN(%d)", it->second->fin);
		}

		if (GlobOpts::withRecv) {
			if (it->second->sent_count > it->second->received_count) {
				printf("   LOST %d times", it->second->sent_count - it->second->received_count);
			}
		}

		if (!it->second->data_retrans_count && !it->second->rdb_count && (it->second->rdb_byte_miss || it->second->rdb_byte_hits)) {
			printf(" FAIL (RDB hit/miss calculalation has failed)!");
		}
		printf("\n");
	}
}


void RangeManager::calculateRetransAndRDBStats() {
	calculateRealLoss(analyse_range_start, analyse_range_end);
}

void RangeManager::calculateRealLoss(map<ulong, ByteRange*>::iterator brIt, map<ulong, ByteRange*>::iterator brIt_end) {
	ByteRange *prev = NULL;
	ulong index = 0;
	int lost_tmp = 0;
	int match_fails_before_end = 0;
	int match_fails_at_end = 0;
	int lost_packets = 0;
	bool prev_pack_lost = false;
	double loss_and_end_limit = 0.01;
	int p_retr_count = 0;

	for (; brIt != brIt_end; brIt++) {
		prev = brIt->second;
		index++;

		if (GlobOpts::withRecv) {
			bool ret = brIt->second->match_received_type();
			if (ret == false) {
				if (index < (ranges.size() * (1 - loss_and_end_limit))) {
					match_fails_before_end++;
					colored_printf(YELLOW, "Failed to match %lu - %lu (%lu - %lu) (index: %lu) on %s\n",
								   relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq),
								   brIt->second->startSeq, brIt->second->endSeq, index, conn->getConnKey().c_str());
					brIt->second->print_tstamps_tcp();
				}
				else
					match_fails_at_end++;
			}
		}

		int rdb_count = brIt->second->rdb_count;
		if (rdb_count && brIt->second->recv_type == RDB) {
			rdb_count -= 1; // Remove the successfull rdb transfer
			brIt->second->rdb_byte_hits = brIt->second->byte_count;
			rdb_byte_hits += brIt->second->byte_count;
		}

		if (brIt->second->recv_type == RDB) {
			rdb_packet_hits++;
		}

		p_retr_count += brIt->second->packet_retrans_count;

		brIt->second->rdb_byte_miss = rdb_count * brIt->second->byte_count;
		rdb_byte_miss += brIt->second->rdb_byte_miss;

		analysed_sent_ranges_count += brIt->second->sent_count;
		analysed_redundant_bytes += brIt->second->byte_count * (brIt->second->data_retrans_count + brIt->second->rdb_count);

		if (brIt->second->byte_count) {
			// Always count 1 for a ByteRange, even though the orignal sent data might have been segmented on the wire.
			//analysed_data_packet_count += 1 + brIt->second->packet_retrans_count;
			//if (brIt->second->packet_sent_count)
			//	printf("SENT COUNT: %d\n", brIt->second->packet_sent_count);
			//analysed_data_packet_count += (brIt->second->packet_sent_count > 0) + brIt->second->packet_retrans_count;
			//analysed_data_packet_count += brIt->second->packet_sent_count;
			analysed_data_packet_count += 1 + brIt->second->packet_retrans_count;
		}

		//printf("sent_count: %d, retrans_count: %d\n", brIt->second->sent_count, brIt->second->retrans_count);
		//assert("FAIL" && (1 + brIt->second->packet_retrans_count == brIt->second->sent_count));

		analysed_syn_count += brIt->second->syn;
		analysed_fin_count += brIt->second->fin;
		analysed_rst_count += brIt->second->rst;

		analysed_pure_acks_count += brIt->second->acked_sent;
		analysed_rdb_packet_count += brIt->second->original_packet_is_rdb;
		analysed_bytes_sent += brIt->second->sent_count * brIt->second->byte_count;
		analysed_packet_count += 1 + brIt->second->packet_retrans_count; // This is the number of (adjusted) packets sent, which will be greater if segmentation offloading is enabled.

		analysed_packet_count += brIt->second->acked_sent; // Count pure acks
		analysed_packet_count += brIt->second->rst; // Count rst packets

		// Range with no bytes
		if (!brIt->second->byte_count) {
			// This is a pure ack with no data transfered first (special case)
			// Normally a pure ack is registered on a range with data
			if (!(brIt->second->syn || brIt->second->fin)) {
				// We already counted this packet with 1 + acked_sent, so remove 1
				analysed_packet_count--;
			}
		}

		/*
		if (brIt->second->acked_sent) {
			printf("ack sent: %d\n", brIt->second->acked_sent);
			colored_printf(YELLOW, "ack sent %lu - %lu (%lu - %lu) : %d\n",
						   relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq),
						   brIt->second->startSeq, brIt->second->endSeq, brIt->second->acked_sent);
		}
		*/
		analysed_retr_packet_count += brIt->second->packet_retrans_count;
		analysed_bytes_retransmitted += brIt->second->data_retrans_count * brIt->second->byte_count;
		analysed_ack_count += brIt->second->ack_count;
		analysed_packet_sent_count += brIt->second->packet_sent_count; // This should be the number of packets found in the dump (same as wireshark and tcptrace)

		if (brIt->second->sent_count != brIt->second->received_count) {
			analysed_lost_ranges_count += (brIt->second->sent_count - brIt->second->received_count);
			analysed_lost_bytes += (brIt->second->sent_count - brIt->second->received_count) * brIt->second->byte_count;
			ulong lost = (brIt->second->sent_count - brIt->second->received_count);

			// Must check if this lost packet is the same packet as for the previous range
			if (prev_pack_lost) {
				for (ulong i = 0; i < brIt->second->lost_tstamps_tcp.size(); i++) {
					for (ulong u = 0; u < prev->lost_tstamps_tcp.size(); u++) {
						if (brIt->second->lost_tstamps_tcp[i].first == prev->lost_tstamps_tcp[u].first) {
							lost -= 1;
							if (!lost) {
								i = brIt->second->lost_tstamps_tcp.size();
								u = prev->lost_tstamps_tcp.size();
							}
						}
					}
				}
			}
			lost_packets += lost;
			prev_pack_lost = true;
		}
		else
			prev_pack_lost = false;

		if (brIt->second->sent_count > 1)
			lost_tmp += brIt->second->sent_count - 1;
		else {
			lost_tmp = 0;
		}
	}

	rdb_packet_misses = analysed_rdb_packet_count - rdb_packet_hits;

#ifdef DEBUG
//	printf("Ranges count: %lu\n", ranges.size());
//	printf("analysed_packet_sent_count: %d\n", analysed_packet_sent_count);
#endif

	if (match_fails_before_end) {
		colored_printf(RED, "%s : Failed to find timestamp for %d out of %ld packets.\n", conn->getConnKey().c_str(), match_fails_before_end, ranges.size());
		colored_printf(RED, "These packest were before the %f%% limit (%d) from the end (%lu), and might be caused by packets being dropped from tcpdump\n",
					   (1 - loss_and_end_limit), (int) (ranges.size() * (1 - loss_and_end_limit)), ranges.size());
	}
#ifndef DEBUG
	if (match_fails_at_end)
		printf("%s : Failed to find timestamp for %d out of %ld packets. These packets were at the end of the stream" \
		       ", so presumable they were just not caught by tcpdump.\n", conn->getConnKey().c_str(), match_fails_at_end, ranges.size());
#endif
}

ByteRange* RangeManager::getHighestAcked() {
	if (highestAckedByteRangeIt == ranges.end())
		return NULL;
	return highestAckedByteRangeIt->second;
}

/*
   Returns duration of connection (in seconds)
*/
uint32_t RangeManager::getDuration() {
	map<ulong, ByteRange*>::iterator brIt_end = ranges.end();
	brIt_end--;
	return getDuration(brIt_end->second);
}

inline double RangeManager::getDuration(ByteRange *brLast) {
	return getTimeInterval(ranges.begin()->second, brLast);
}


void RangeManager::calculateLatencyVariation() {
	registerRecvDiffs();
	calculateClockDrift();
	doDriftCompensation();
}


void RangeManager::registerRecvDiffs() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	timeval *last_app_layer_tstamp = NULL;

	for (; it != it_end; it++) {
		if (!it->second->received_count) {
			continue;
		}

		if (!GlobOpts::transport) {
			if (it->second->app_layer_latency_tstamp)
				last_app_layer_tstamp = &it->second->received_tstamp_pcap;
			assert(last_app_layer_tstamp != NULL && "last_app_layer_tstamp is invalid!");
		}

		/* Calculate diff and check for lowest value */
		it->second->match_received_type();
		it->second->calculateRecvDiff(last_app_layer_tstamp);
	}

	if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
		cerr << "SendTime: " << it->second->getSendTime()->tv_sec << "."
			 << it->second->getSendTime()->tv_usec << endl;
		cerr << "RecvTime: ";
		if (it->second->getRecvTime() != NULL)
			cerr << it->second->getRecvTime()->tv_sec;
		cerr << endl;
	}
}


void RangeManager::doDriftCompensation() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	for (; it != it_end; it++) {
		double diff = (double) it->second->getRecvDiff();
		/* Compensate for drift */
		diff -= (drift * getDuration(it->second));
		it->second->setRecvDiff(diff);

		if (diff < lowestRecvDiff) {
			lowestRecvDiff = diff;
		}
		if(GlobOpts::debugLevel==4 || GlobOpts::debugLevel==5){
			cerr << "dcDiff: " << diff << endl;
		}
	}
}

/* Calculate clock drift on CDF */
int RangeManager::calculateClockDrift() {
	map<ulong, ByteRange*>::iterator startIt;
	map<ulong, ByteRange*>::reverse_iterator endIt;
	long minDiffStart = LONG_MAX;
	long minDiffEnd = LONG_MAX;
	struct timeval minTimeStart, minTimeEnd, tv;
	float time, tmpDrift;
	timerclear(&minTimeStart);
	timerclear(&minTimeEnd);

	startIt = ranges.begin();

	const uint64_t n = std::min(200UL, ranges.size() / 2 - 1);

	for (uint64_t i = 0; i < n; i++) {
		if (startIt->second->getRecvDiff() < minDiffStart) {
			minDiffStart = startIt->second->getRecvDiff();
			minTimeStart = *(startIt->second->getSendTime());
		}
		startIt++;
	}

	endIt = ranges.rbegin();
	for (uint64_t i = 0; i < n; i++) {
		if (endIt->second->getRecvDiff() < minDiffEnd) {
			minDiffEnd = endIt->second->getRecvDiff();
			minTimeEnd = *(endIt->second->getSendTime());
		}
		endIt++;
	}

	if (!timerisset(&minTimeEnd) || !timerisset(&minTimeStart)) {
		printf("Timvals have not not populated! minTimeStart is zero: %s, minTimeEnd is zero: %s\n",
			   !timerisset(&minTimeStart) ? "Yes" : "No", !timerisset(&minTimeEnd) ? "Yes" : "No");
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	/* Get time interval between values */
	timersub(&minTimeEnd, &minTimeStart, &tv);
	time = tv.tv_sec + (tv.tv_usec / 1000000.0);
	tmpDrift = (float) (minDiffEnd - minDiffStart) / time;

	if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
		cerr << "startMin: " << minDiffStart << endl;
		cerr << "startTime: " << minTimeStart.tv_sec << "." << minTimeStart.tv_usec << endl;
		cerr << "endMin: " << minDiffEnd << endl;
		cerr << "endTime: " << minTimeEnd.tv_sec << "." << minTimeEnd.tv_usec << endl;
		cerr << "Time: " << time << endl;
		cerr << "Clock drift: " << tmpDrift << " ms/s" << endl;
	}
	drift = tmpDrift;
	return 0;
}

void RangeManager::makeByteLatencyVariationCDF() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;
	map<const long, int>::iterator element, end, endAggr;
	end = byteLatencyVariationCDFValues.end();
	endAggr = GlobStats::byteLatencyVariationCDFValues.end();

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff() - lowestRecvDiff;
		element = byteLatencyVariationCDFValues.find(diff);

		if (element != end) {
			/*  Add bytes to bucket */
			//printf("setting getNumBytes: %d\n", it->second->getNumBytes());
			//element->second = element->second + it->second->getOrinalPayloadSize();
			element->second = element->second + it->second->getNumBytes();
		} else {
			/* Initiate new bucket */
			byteLatencyVariationCDFValues.insert(pair<long, int>(diff, it->second->getNumBytes()));
		}
		if (GlobOpts::aggregate) {
			element = GlobStats::byteLatencyVariationCDFValues.find(diff);
			if (element != endAggr) {
				/*  Add bytes to bucket */
				element->second = element->second + it->second->getNumBytes();
			} else {
				/* Initiate new bucket */
				GlobStats::byteLatencyVariationCDFValues.insert(pair<long, int>(diff, it->second->getNumBytes()));
			}
		}

		if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
			it->second->printValues();
		}
	}
	GlobStats::totNumBytes += getNumBytes();
}


void RangeManager::writeSentTimesAndQueueingDelayVariance(const uint64_t first_tstamp, ofstream& stream) {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	//const long first = TV_TO_MS(ranges[0]->sent_tstamp_pcap[0]);

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff() - lowestRecvDiff;
		int64_t ts = TV_TO_MS(it->second->sent_tstamp_pcap[it->second->send_tcp_stamp_recv_index]);

		assert(diff >= 0 && "Negative diff, this shouldn't happen!");

		LatencyItem lat(((uint64_t) ts) - first_tstamp, diff);
		stream << lat << endl;
	}
}

void RangeManager::writeByteLatencyVariationCDF(ofstream *stream) {
	map<const long, int>::iterator nit, nit_end;
	double cdfSum = 0;
	char print_buf[300];
	nit = byteLatencyVariationCDFValues.begin();
	nit_end = byteLatencyVariationCDFValues.end();

	if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
		cerr << "lowestRecvDiff: " << lowestRecvDiff << endl;
	}

	*stream << "#------ Drift : " << drift << "ms/s ------" << endl;
	*stream << "#Relative delay      Percentage" << endl;
	for (; nit != nit_end; nit++) {
		cdfSum += (double)(*nit).second / getNumBytes();
		sprintf(print_buf, "time: %10ld    CDF: %.10f", (*nit).first, cdfSum);
		*stream << print_buf << endl;
	}
}

/*
void RangeManager::writePacketLatencyVariationValues(ofstream *stream) {

	timeval tv;
	long time;
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff() - lowestRecvDiff;
		tv = sent_tstamp_pcap[0];
		time = tv.tv_sec * 1000 + (tv.tv_usec / 1000.0);

		packetLatencyVariationValues.insert(pair<long, uint16_t>(start_seq, diff)

		if (GlobOpts::aggregate) {
	}

	//multimap<const long, int> packetLatencyVariationValues
	map<const long, int>::iterator nit, nit_end;

void RangeManager::writePacketLatencyVariationValues(ofstream *stream) {

	nit = packetLatencyVariationValues.begin();
	nit_end = packetLatencyVariationValues.end();
	for(; nit != nit_end; nit++){
		cdfSum += (double) (*nit).second / getNumBytes();
		sprintf(print_buf, "time: %10ld    CDF: %.10f", (*nit).first, cdfSum);
		*stream << print_buf << endl;
	}
}
*/



/*
 * Sum two loss interval values together
 */
LossInterval& LossInterval::operator+=(const LossInterval& rhs) {
	count += rhs.count;
	bytes += rhs.bytes;
	return *this;
}

/*
 * Set total values for the loss interval
 */
void LossInterval::add_total(double count, double bytes) {
	total_count += count;
	total_bytes += bytes;
}

void RangeManager::calculateLossGroupedByInterval(const uint64_t first, vector<LossInterval>& all_loss, vector<LossInterval>& loss) {
	assert(GlobOpts::withRecv && "Writing loss grouped by interval requires receiver trace");

	vector< pair<uint32_t, timeval> >::iterator lossIt, lossEnd;
	vector<timeval>::iterator sentIt, sentEnd;
	map<ulong, ByteRange*>::iterator range;

	// Extract total values from ranges
	typedef vector<double> lossvec;
	auto_ptr<lossvec> total_count( new lossvec() );
	auto_ptr<lossvec> total_bytes( new lossvec() );
	lossvec& tc = *total_count.get();
	lossvec& tb = *total_bytes.get();

	for (range = analyse_range_start; range != analyse_range_end; ++range) {
		sentIt = range->second->sent_tstamp_pcap.begin();
		sentEnd = range->second->sent_tstamp_pcap.end();

		// Place sent counts and byte counts in the right bucket
		for (; sentIt != sentEnd; ++sentIt)
		{
			uint64_t relative_ts = TV_TO_MS(*sentIt) - first;
			uint64_t bucket_idx = relative_ts / GlobOpts::lossAggrMs;

			while (bucket_idx >= tc.size()) {
				tc.push_back(0);
				tb.push_back(0);
			}

			if (bucket_idx == 62) {
				printf("\ntimestamp: %ld\n", TV_TO_MS(*sentIt));
				printf("%s wut pcap ts: %lu tcp ts: %lu rdb ts: %lu\n", conn->getConnKey().c_str(), 
						range->second->sent_tstamp_pcap.size(), 
						range->second->tstamps_tcp.size(),
						range->second->rdb_tstamps_tcp.size()
						); 
			 }

			tc[bucket_idx] += 1;
			tb[bucket_idx] += range->second->byte_count;
		}
	}

	// Calculate loss values
	for (range = analyse_range_start; range != analyse_range_end; ++range) {
		lossIt = range->second->lost_tstamps_tcp.begin();
		lossEnd = range->second->lost_tstamps_tcp.end();

		// Place loss values in the right bucket
		for (; lossIt != lossEnd; ++lossIt) {
			uint64_t relative_ts = TV_TO_MS(lossIt->second) - first;
			uint64_t bucket_idx = relative_ts / GlobOpts::lossAggrMs;

			while (bucket_idx >= loss.size()) {
				loss.push_back(LossInterval(0, 0));
			}

			loss[bucket_idx] += LossInterval(1, range->second->byte_count);
		}
	}

	const uint64_t num_buckets = loss.size();
	while (num_buckets >= all_loss.size()) {
		all_loss.push_back(LossInterval(0, 0));
	}

	// Set total values
	for (uint64_t idx = 0; idx < num_buckets; ++idx) {
		/*if (idx == 62//71) {
			printf("\n\n%s WAT\ntc: %g, tb: %g\n\n", conn->getConnKey().c_str(), tc[idx], tb[idx]);
		}*/

		all_loss[idx] += loss[idx];
		all_loss[idx].add_total(tc[idx], tb[idx]);
		loss[idx].add_total(tc[idx], tb[idx]);
	}
}

/*
  Writes the loss stats for the connection over time.
  The slice_interval defines the interval for which to aggregate the loss.
*/
/*
void RangeManager::write_loss_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *loss_retrans_out, FILE *loss_loss_out) {
	map<ulong, ByteRange*>::iterator brIt, brIt_end;
	int lost_count = 0;
	int retrans_count = 0;
	timeval next, t_slice, next_tmp;

	brIt = analyse_range_start;
	brIt_end = analyse_range_end;
	t_slice.tv_sec = slice_interval;
	t_slice.tv_usec = 0;
	timeradd(&(brIt->second->sent_tstamp_pcap[0]), &t_slice, &next);

	fprintf(loss_retrans_out, "%45s", conn->getConnKey().c_str());
	if (loss_loss_out)
		fprintf(loss_loss_out, "%45s", conn->getConnKey().c_str());

	for (; brIt != brIt_end; brIt++) {

		// Print slice value and find next slice time
		while (!timercmp(&(brIt->second->sent_tstamp_pcap[0]), &next, <)) {
			fprintf(loss_retrans_out, ",%10d", retrans_count);
			if (loss_loss_out)
				fprintf(loss_loss_out, ",%10d", lost_count);
			lost_count = 0;
			retrans_count = 0;
			memcpy(&next_tmp, &next, sizeof(struct timeval));
			timeradd(&next_tmp, &t_slice, &next);
			timeslice_count--;
		}

		retrans_count += brIt->second->packet_retrans_count;
		if (loss_loss_out)
			lost_count += brIt->second->sent_count - brIt->second->received_count;
	}

	// Pad remaining slices with zeroes
	while (timeslice_count) {
		fprintf(loss_retrans_out, ",%10d", 0);
		if (loss_loss_out)
			fprintf(loss_loss_out, ",%10d", 0);
		timeslice_count--;
	}

	fprintf(loss_retrans_out, "\n");
	if (loss_loss_out)
		fprintf(loss_loss_out, "\n");
}
*/

/*
  Generates the retransmission data for the R files.
  The latency for each range is stored based on the
  number of tetransmissions for the range.
  The aggregation option controls of per stream or only
  aggregated result files should be made.
*/
void RangeManager::genAckLatencyFiles(long first_tstamp, const string& connKey) {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	vector<std::tr1::shared_ptr<vector <LatencyItem> > > diff_times;
	ulong num_retr_tmp;
	int diff_tmp;
	ulong send_time_ms;

	//long first_tstamp = TV_TO_MS(ranges[0]->sent_tstamp_pcap[0]);

	for (; it != it_end; it++) {
		diff_tmp = it->second->getSendAckTimeDiff(this);
		if (diff_tmp > 0) {
			num_retr_tmp = it->second->getNumRetrans();

			send_time_ms = TV_TO_MS(it->second->sent_tstamp_pcap[0]);
			//printf("%lu.%lu -> %lu\n", it->second->sent_tstamp_pcap[0].tv_sec, it->second->sent_tstamp_pcap[0].tv_usec, send_time_ms);

			send_time_ms -= first_tstamp;

			if (num_retr_tmp >= GlobStats::ack_latency_vectors.size()) {
				globStats->update_retrans_filenames(num_retr_tmp + 1);
			}
			// all
			GlobStats::ack_latency_vectors[0]->push_back(LatencyItem(send_time_ms, diff_tmp));
			if (num_retr_tmp) {
				// Retrans vector for that number of retransmissions
				GlobStats::ack_latency_vectors[num_retr_tmp]->push_back(LatencyItem(send_time_ms, diff_tmp));
			}

			// Add value to be written to file
			if (!(GlobOpts::aggOnly)) {
				if (num_retr_tmp >= diff_times.size()) {
					globStats->update_vectors_size(diff_times, num_retr_tmp +1);
				}
				diff_times[0]->push_back(LatencyItem(send_time_ms, diff_tmp));
				if (num_retr_tmp) {
					diff_times[num_retr_tmp]->push_back(LatencyItem(send_time_ms, diff_tmp));
				}
			}
		}
	}
	// Creating the file streams
	if (!(GlobOpts::aggOnly)) {
		vector<string> filenames;
		stringstream filename_tmp;

		for (unsigned long int i = 0; i < diff_times.size(); i++) {
			filename_tmp.str("");
			filename_tmp << GlobStats::retrans_filenames[i] << connKey << ".dat";
			filenames.push_back(filename_tmp.str());
		}

		// Add the output dir and custom prefix string to filenames
		globStats->prefix_filenames(filenames);

		for (ulong num_retr_tmp = 0; num_retr_tmp < filenames.size(); num_retr_tmp++) {
			ofstream stream;
			stream.open(filenames[num_retr_tmp].c_str(), ios::out);

			vector<LatencyItem>& vec_retr = *diff_times[num_retr_tmp];
			for (unsigned long int i = 0; i < diff_times[num_retr_tmp]->size(); i++) {
				stream << vec_retr[i] << endl;
			}
			stream.close();
		}
	}
}
