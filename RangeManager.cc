#include <memory>
#include <stdexcept>

#include "RangeManager.h"
#include "Connection.h"
#include "ByteRange.h"
#include "util.h"
#include "color_print.h"


#define RECURSION_LEVEL 1500

const char *received_type_str[] = {"DEF", "DTA", "RDB", "RTR"};

RangeManager::~RangeManager() {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	for (; it != it_end; it++) {
		delete it->second;
	}
}


#define STR_ABSOLUTE_SEQNUM_PAIR(seq_start, seq_end) absolute_seq_pair_str(seq_start, END_SEQ(seq_end)).c_str()
#define STR_SEQNUM_PAIR(seq_start, seq_end) seq_pair_str(seq_start, seq_end).c_str()
#define STR_PRELATIVE_SEQNUM_PAIR(seq_start, seq_end) seq_pair_str(get_print_seq(seq_start), get_print_seq(seq_end)).c_str()

string seq_pair_str(seq64_t start, seq64_t end) {
	return to_string(start) + "," + to_string(end);
}

string RangeManager::absolute_seq_pair_str(seq64_t start, seq64_t end) {
	return seq_pair_str(absolute_seq(start), absolute_seq(end));
}

/*
  Based on the relative sequence number (starting at 0 for the stream)
  return the absolute sequence number (as found in the TCP header)
 */
seq32_t RangeManager::absolute_seq(seq64_t seq) {
	seq64_t wrap_index;
	wrap_index = (firstSeq + seq) / 4294967296L;
	//	printf("absolute_seq: seq: %llu, first + seq: %llu, wrap_index: %lu\n", seq, firstSeq + seq, wrap_index);
	seq64_t res = seq + firstSeq;
	res -= ((seq64_t) wrap_index * 4294967296L);
	//printf("absolute_seq  ret: %lu\n", res);
	return (seq32_t) res;
}

string RangeManager::strByteRange(seq64_t seq_start, seq64_t seq_end) {
	return strfmt("ByteRange(%lld)[%s (%s)] ", seq_end - seq_start,
				  STR_SEQNUM_PAIR(seq_start, seq_end),
				  STR_ABSOLUTE_SEQNUM_PAIR(seq_start, seq_end)
				  );
}

/*
  If relative_seq option is enabled, the seq argument is returned as is.
  If disabled, it will convert the seq to the absolute sequence number (the actual value found in the TCP header)
 */
seq64_t RangeManager::get_print_seq(seq64_t seq) {
	if (GlobOpts::relative_seq)
		return seq;
	return absolute_seq(seq);
}

/* Register all bytes with a common send time as a range */
void RangeManager::insertSentRange(sendData *sd) {
	seq64_t startSeq = sd->data.seq;
	seq64_t endSeq = sd->data.endSeq;

#ifdef DEBUG
	int debug_print = 0;
	if (debug_print) {
		printf("\ninsertSentRange (%llu): (%s) (%s), retrans: %d, is_rdb: %d\n",
               (seq64_t) (endSeq - startSeq),
			   STR_ABSOLUTE_SEQNUM_PAIR(startSeq, endSeq),
			   STR_SEQNUM_PAIR(startSeq, endSeq), sd->data.retrans, sd->data.is_rdb);
	}
#endif
	insertByteRange(startSeq, endSeq, INSERT_SENT, &(sd->data), 0);

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
		lastSeq = startSeq + sd->data.payloadSize;
#ifdef DEBUG
		if (debug_print) {
			printf("-------New range equivalent with packet---------\n");
			printf("%s - inserted Range with startseq: %llu\n", conn->getConnKey().c_str(), get_print_seq(startSeq));
		}
#endif
	}
	/* Check for instances where sent packets are lost from the packet trace */
	else if (startSeq > lastSeq) {
		// This is most probably the ack on the FIN ack from receiver, so ignore
		if (sd->data.payloadSize != 0) {
			if (GlobOpts::validate_ranges) {
				fprintf(stderr, "RangeManager::insertRange: Missing byte in send range in conn '%s''\n",
					   conn->getConnKey().c_str());
				fprintf(stderr, "Expected seq: %llu but got %llu\n", (seq64_t) lastSeq, startSeq);
				fprintf(stderr, "Absolute: lastSeq: %llu, startSeq: %llu. Relative: lastSeq: %llu, startSeq: %llu\n",
						(seq64_t) lastSeq, startSeq, get_print_seq(lastSeq), get_print_seq(startSeq));
				fprintf(stderr, "This is an indication that tcpdump has dropped packets while collecting the trace.\n");
				warn_with_file_and_linenum(__FILE__, __LINE__);
			}
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
				fprintf(stderr, "INCORRECT: %u\n", sd->data.payloadSize);
				warn_with_file_and_linenum(__FILE__, __LINE__);
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
				printf("Adding %llu redundant bytes to connection\n", (endSeq +1 - startSeq));
			}
#endif
		} else { /* Old and new bytes: Bundle */
#ifdef DEBUG
			if (debug_print)
				printf("-------Overlap: registering some bytes---------");

			if ((endSeq - startSeq) != sd->data.payloadSize) {
				fprintf(stderr, "Data len incorrect!\n");
				warn_with_file_and_linenum(__FILE__, __LINE__);
			}
#endif
			lastSeq = startSeq + sd->data.payloadSize;
#ifdef DEBUG
			if (lastSeq != (endSeq)) {
				fprintf(stderr, "INCORRECT: %u\n", sd->data.payloadSize);
				warn_with_file_and_linenum(__FILE__, __LINE__);
			}
#endif
		}
	}
}

void RangeManager::insertReceivedRange(sendData *sd) {
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

	if (DEBUGL_RECEIVER(5)) {
		cerr << "Inserting receive data: startSeq=" << get_print_seq(tmpSeg.seq)
			 << ", endSeq=" << get_print_seq(tmpSeg.endSeq) << endl;
		if (tmpSeg.seq == 0 || tmpSeg.endSeq == 0) {
			cerr << "Erroneous seq." << endl;
		}
	}
	/* Insert all packets into data structure */
	insertByteRange(tmpSeg.seq, tmpSeg.endSeq, INSERT_RECV, &tmpSeg, 0);
}

/*
  This inserts the the data into the ranges map.
  It's called both with sent end received data ranges.
*/
bool RangeManager::insertByteRange(seq64_t start_seq, seq64_t end_seq, insert_type itype, DataSeg *data_seg, int level) {
	ByteRange *last_br = NULL;
	map<seq64_t, ByteRange*>::iterator brIt, brIt_end;
	brIt_end = ranges.end();
	brIt = brIt_end;

#ifdef DEBUG
	int debug_print = 0;
	//if (TV_TO_MS(data_seg->tstamp_pcap) == 1396710194676) {
	//	printf("\n\nHEEEEEEI sent:%d level:%d\n\n", sent, level);
	//	printf("%s\n", conn->getConnKey().c_str());
	//	debug_print = 1;
	//}
	//debug_print = 1;

//	if (data_seg->payloadSize == 1) {
//		debug_print = 1;
//	}
	//if (start_seq >= 222036 && start_seq <= 232036)
	//	debug_print = 1;

	//if (start_seq < 1000)
	//	debug_print = 1;
	//
	//if (start_seq >= 21660765)
	//	exit(0);

	//if (start_seq >= 844017633 && start_seq <= 844035633)
	//	debug_print = 1;
	//fprintf(stderr, "level: %d\n", level);

	char prefix[100];
	int i;
	int indent = level * 3;
	indent = indent < 15 ? indent : 15;
	for (i = 0; i < indent; i++) {
		prefix[i] = ' ';
	}
	sprintf(prefix + indent, "%d", level);

#define indent_print(format, args...) printf("%s " format, prefix, args)
#define indent_print2(format) printf("%s " format, prefix)
#endif

	bool this_is_rdb_data = data_seg->is_rdb && data_seg->rdb_end_seq > start_seq;

#ifdef DEBUG
	if (debug_print) {
		if (!level)
			printf("\n");
		indent_print("insertByteRange0 (%llu): (%s) (%s), itype: %d, "
					 "retrans: %d, is_rdb: %d, SYN: %d, FIN: %d, RST: %d, tstamp_tcp: %u\n",
					 end_seq - start_seq, STR_SEQNUM_PAIR(start_seq, end_seq), STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq),
					 itype, data_seg->retrans, data_seg->is_rdb,
					 !!(data_seg->flags & TH_SYN), !!(data_seg->flags & TH_FIN),
					 !!(data_seg->flags & TH_RST), data_seg->tstamp_tcp);
	}
#endif

	// An ack
	if (start_seq == end_seq) {

		if (itype == INSERT_SENT) {
			analysed_sent_pure_ack_count++;
		}

		//If not SYN or FIN, it's pure ack (or RST)
		if (!(data_seg->flags & TH_SYN) && !(data_seg->flags & TH_FIN) && !(data_seg->flags & TH_RST)) {
			// If start seq -1 exists, use that
			if (ranges.find(start_seq -1) != brIt_end) {
				start_seq -= 1;
				end_seq = start_seq;
#ifdef DEBUG
				if (debug_print) {
					indent_print("Pure ack! Decrease SEQ with 1: %llu\n", start_seq);
				}
#endif
			}
		}
	}

	brIt = ranges.find(start_seq);

	// Doesn't exist
	if (brIt == brIt_end) {
#ifdef DEBUG
		if (debug_print) {
			indent_print("NOT FOUND: itype:%d, %s (%llu)\n",
						 itype, STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq), end_seq - start_seq);
		}
#endif
		if (itype == INSERT_RECV) {
#ifdef DEBUG
			indent_print("Received non-existent byte range (%llu): (%s) (%s), itype: %d, retrans: %d, is_rdb: %d\n",
						 end_seq == start_seq ? 0 : end_seq - start_seq +1,
						 STR_SEQNUM_PAIR(start_seq, end_seq), STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq),
						 itype, data_seg->retrans, data_seg->is_rdb);
			indent_print("Connection: %s\n", conn->getConnKey().c_str());
#endif
			warn_with_file_and_linenum(__FILE__, __LINE__);
		}

#ifdef DEBUG
		if (debug_print) {
			indent_print("Adding: %s (start_seq: %llu)\n",
						 STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq), start_seq);
		}
#endif

		// Ack / syn-ack /rst
		if (end_seq == start_seq) {
#ifdef DEBUG
			if (itype == INSERT_RECV) {
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
			last_br->packet_retrans_count += data_seg->retrans;
			last_br->rdb_count += data_seg->is_rdb;
			if (data_seg->flags & TH_SYN) {
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
				//last_br->acked_sent++;
			}
			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo,
								   data_seg->tstamp_pcap, this_is_rdb_data,
								   (last_br->syn | last_br->rst | last_br->fin) ? ST_PKT : ST_PURE_ACK);
			ranges.insert(pair<seq64_t, ByteRange*>(start_seq, last_br));
			return true;
		}

		map<seq64_t, ByteRange*>::iterator lowIt, highIt;
		highIt = ranges.upper_bound(end_seq);
		seq64_t new_end_seq = end_seq;

		// This may be retransmission or packet containing rdb data
		if (start_seq < lastSeq) {
#ifdef DEBUG
			// Some Non-rdb packets are registered as RDB because of segmentation-offloading
			if (debug_print) {
				indent_print("FOUND RETRANS: start_seq < lastSeq: %llu < %llu\n", start_seq, lastSeq);
			}
#endif
			seq64_t lower = start_seq;
			lowIt = ranges.lower_bound(lower);
			if (lowIt != ranges.begin())
				lowIt--;
			if (lowIt == highIt) {
				printf("lowIt == highIt, start_seq: %llu\n", start_seq);
				printf("lowIt: (%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(lowIt->second->startSeq, lowIt->second->endSeq));
				assert(0);
			}
			// Search for existing ranges for this data
			for (; lowIt != highIt && lowIt != highIt;) {
				// Found existing range
				// The existing range is bigger than the data to be registered, so we split the existing range
				if (lowIt->second->startSeq <= start_seq && lowIt->second->endSeq >= start_seq) {
#ifdef DEBUG
					if (lowIt->second->startSeq == start_seq) {
						fprintf(stderr, "New Data is at the beginning of existing range!!\n");
						fprintf(stderr, "Existing Range: %s\n", STR_ABSOLUTE_SEQNUM_PAIR(lowIt->second->startSeq, lowIt->second->endSeq));
						fprintf(stderr, "New data Range: %s\n", STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq));
					}
					//assert(lowIt->second->startSeq != start_seq && "New Data is at beginning of existing range!!\n");
#endif
					ByteRange *cur_br = lowIt->second;
					int start_matches = (start_seq == cur_br->startSeq);
					int end_matches = (end_seq == cur_br->endSeq);
					int insert_more_recursively = 0;

					assert(!(start_matches && end_matches) && "BOTH");
#ifdef DEBUG
					if (debug_print) {
						indent_print("ITYPE: %d, rdb: %d, retrans: %d\n", itype, data_seg->is_rdb, data_seg->retrans);
						indent_print("Found existing range with matching data\n            for: %s!\n",
									 STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq));
						indent_print("Old Range        : %s (%llu)\n", STR_ABSOLUTE_SEQNUM_PAIR(cur_br->startSeq, cur_br->endSeq),
									 (cur_br->endSeq - cur_br->startSeq) +1);
					}
#endif
					if (itype != INSERT_SOJOURN) {
						// Splitting existing range

						ByteRange *range_received;
						ByteRange *new_br;
						if (start_matches) {
							new_br = cur_br->splitEnd(end_seq, cur_br->endSeq);
							if (data_seg->flags & TH_FIN) {
								cur_br->fin += 1;
							}
#ifdef DEBUG
							if (debug_print) {
								indent_print("New Range 1      : %s (%llu)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(cur_br->startSeq, cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
								indent_print("New Range 2      : %s (%llu)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(new_br->startSeq, new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
							}
#endif
							range_received = cur_br;
						}
						else if (end_matches) {
							new_br = cur_br->splitEnd(start_seq, cur_br->endSeq);
							if (data_seg->flags & TH_FIN) {
								new_br->fin = 1;
							}
#ifdef DEBUG
							if (debug_print) {
								indent_print("New Range 1      : %s (%llu)\n", STR_ABSOLUTE_SEQNUM_PAIR(cur_br->startSeq, cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
								indent_print("New Range 2      : %s (%llu)\n", STR_ABSOLUTE_SEQNUM_PAIR(new_br->startSeq, new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
							}
#endif
							range_received = new_br;
						}
						// New data fits into current range
						else if (end_seq < cur_br->endSeq) {
							// Split in the middle
							new_br = cur_br->splitEnd(start_seq, cur_br->endSeq);
							if (data_seg->flags & TH_FIN) {
								new_br->fin = 1;
							}
							ByteRange *new_last = new_br->splitEnd(end_seq, new_br->endSeq);
#ifdef DEBUG
							if (debug_print) {
								indent_print("New Range 1      : %s (%llu)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(cur_br->startSeq, cur_br->endSeq), (cur_br->endSeq - cur_br->startSeq) +1);
								indent_print("New Range 2      : %s (%llu)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(new_br->startSeq, new_br->endSeq), (new_br->endSeq - new_br->startSeq) +1);
								indent_print("New Range 3      : %s (%llu)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(new_last->startSeq, new_last->endSeq), (new_last->endSeq - new_last->startSeq) +1);
							}
#endif
							ranges.insert(pair<seq64_t, ByteRange*>(new_last->startSeq, new_last));
							range_received = new_br;
						}
						// New data spans beyond current range
						else {
							new_br = cur_br->splitEnd(start_seq, cur_br->endSeq);
							range_received = new_br;
							insert_more_recursively = 1;
						}
						ranges.insert(pair<seq64_t, ByteRange*>(new_br->startSeq, new_br));

						if (itype == INSERT_SENT) {
							sent_type s_type = ST_NONE;
							if (!level)
								s_type = ST_RTR;

							range_received->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, s_type);
							range_received->data_retrans_count++;

							//cur_br->retrans_count += data_seg->retrans;
							range_received->rdb_count += data_seg->is_rdb;
#ifdef DEBUG
							//printf("data_seg->retrans: %d\n", data_seg->retrans);
							if (data_seg->retrans == 0) {
								fprintf(stderr, "NOT RETRANS? Conn: %s\n", conn->getConnKey().c_str());
								indent_print("range_received : %s (%d)\n",
											 STR_ABSOLUTE_SEQNUM_PAIR(range_received->startSeq, range_received->endSeq), range_received->getNumBytes());

							}
							//assert("Retrans?" && data_seg->retrans != 0);

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
						else if (itype == INSERT_RECV) {
							range_received->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
							if (!level) {
								range_received->packet_received_count++;
							}
						}
						else if (itype == INSERT_SOJOURN) {
							colored_printf(RED, "Sojourn not handled 1!!\n");
							assert(0);
						}
						if (insert_more_recursively) {
							//indent_print("Recursive call2: brIt->endseq: %llu, endseq: %llu\n", brIt->second->endSeq, end_seq);
							return insertByteRange(new_br->endSeq, end_seq, itype, data_seg, level +1);
						}
					}// END if (itype != INSERT_SOJOURN)
					else {
						//brIt->second->addSegmentEnteredKernelTime(brIt->second->endSeq, data_seg->tstamp_pcap);
						//int start_matches = (start_seq == cur_br->startSeq);
						//int end_matches = (end_seq == cur_br->endSeq);
						//printf("INSERT_SOJOURN\n");
						if (start_matches) {
							assert(0);
							if (end_seq < cur_br->endSeq) {
								bool ret = cur_br->addSegmentEnteredKernelTime(cur_br->endSeq, data_seg->tstamp_pcap);
								if (!ret) {
									printf("SOJOURN DEBUG 5\n");
								}
							}
							else {
								assert(0);
							}
						}
						else if (end_matches) {
							//assert(cur_br->sojourn_tstamps.size());
							bool ret = cur_br->addSegmentEnteredKernelTime(data_seg->endSeq, data_seg->tstamp_pcap);
							if (!ret) {
								printf("SOJOURN DEBUG 5\n");
							}
						}
						// Seq range fits in current range
						else if (end_seq < cur_br->endSeq) {
							bool ret = cur_br->addSegmentEnteredKernelTime(end_seq, data_seg->tstamp_pcap);
							if (!ret) {
								printf("SOJOURN DEBUG 4\n");
							}
						}
						// New data spans beyond current range
						else {
							insert_more_recursively = 1;
							//indent_print("New data spans beyond current range. Range(%s), data end: %llu\n", STR_ABSOLUTE_SEQNUM_PAIR(cur_br->startSeq, cur_br->endSeq), end_seq);
						}
						if (insert_more_recursively) {
							//indent_print("Sojourn recursive call2: brIt->endseq: %llu, endseq: %llu\n", cur_br->endSeq, end_seq);
							return insertByteRange(cur_br->endSeq, end_seq, itype, data_seg, level +1);
						}
					}
					return true;
				}
				else
					lowIt++;
			}
		}

		if (itype == INSERT_SENT) {
#ifdef DEBUG
			if (debug_print) {
				indent_print("data_seg->is_rdb: %d, this_is_rdb_data: %d\n", data_seg->is_rdb, this_is_rdb_data);
				indent_print("data_seg->rdb_end_seq > start_seq: %llu > %llu: %d\n", get_print_seq(data_seg->rdb_end_seq), get_print_seq(start_seq), data_seg->rdb_end_seq > start_seq);
			}
#endif
			last_br = new ByteRange(start_seq, new_end_seq);
			last_br->original_payload_size = data_seg->payloadSize;
			last_br->original_packet_is_rdb = data_seg->is_rdb;

			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, data_seg->is_rdb ? ST_NONE : ST_PKT);
			if (data_seg->flags & TH_SYN) {
				assert("SYN" && 0);
				last_br->syn = 1;
			}
			else if (data_seg->flags & TH_FIN) {
				last_br->fin = 1;
			}
#ifdef DEBUG
			if (data_seg->retrans || this_is_rdb_data) {
				if (debug_print) {
					printf("data_seg->retrans: %d\n", data_seg->retrans);
					printf("this_is_rdb_data: %d\n", this_is_rdb_data);
					indent_print("insertByteRange2 (%llu): (%s) (%s), itype: %d, retrans: %d, is_rdb: %d, SYN: %d, FIN: %d, RST: %d\n",
								 end_seq - start_seq,
								 STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq), STR_SEQNUM_PAIR(start_seq, end_seq),
								 itype, data_seg->retrans, data_seg->is_rdb,
								 !!(data_seg->flags & TH_SYN), !!(data_seg->flags & TH_FIN), !!(data_seg->flags & TH_RST));
				}
				//assert(this_is_rdb_data == 0 && "Shouldn't be RDB?!\n");
				//throw std::logic_error(strfmt("Expected either RDB or retrans packet: %s, Type: %d, Conn: %s\n",
				//							  strByteRange(start_seq, end_seq).c_str(), itype, conn->getConnKey().c_str()));
			}

			if ((new_end_seq - start_seq) > 100) {
				if (debug_print) {
					indent_print("Inserting new big range: %llu\n", (new_end_seq - start_seq +1));
					indent_print("original_payload_size: %d\n", last_br->original_payload_size);
				}
			}
#endif
			ranges.insert(pair<seq64_t, ByteRange*>(start_seq, last_br));
		}
#ifdef DEBUG
		else if (itype == INSERT_RECV) {
			// This data is only in the receiver dump
			if (start_seq > lastSeq) {
				last_br = new ByteRange(start_seq, end_seq);
				last_br->original_payload_size = data_seg->payloadSize;
				last_br->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
				if (!level) {
					last_br->packet_received_count++;
				}

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
				ranges.insert(pair<seq64_t, ByteRange*>(start_seq, last_br));
			}
		}
		else if (itype == INSERT_SOJOURN) {
#ifdef DEBUG
			throw std::logic_error("Sojourn not handled 2: in insertByteRange:"
								   "seq: " + to_string(start_seq) +
								   ", end seq: " + to_string(end_seq) +
								   ", Type: " + to_string(itype)
				);
#endif
		}
#endif
	}
	// Exists in map
	else {
#ifdef DEBUG
		if (debug_print) {
			indent_print("FOUND START: itype:%d, %s (%llu)\n", itype, STR_ABSOLUTE_SEQNUM_PAIR(start_seq, end_seq), end_seq - start_seq);
			indent_print("brIt(%llu): %s, new endseq: %llu (%llu, %llu)\n", brIt->second->endSeq - brIt->second->startSeq,
						 STR_PRELATIVE_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq), get_print_seq(end_seq),
						 brIt->second->startSeq, get_print_seq(brIt->second->startSeq));

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
					indent_print("Register SYN/SYN-ACK or FIN/FIN-ACK on type '%d'\n", itype);
					indent_print("SYN: %d, FIN: %d, ACK: %d\n", (data_seg->flags & TH_SYN) == TH_SYN, (data_seg->flags & TH_FIN) == TH_FIN, (data_seg->flags & TH_ACK) == TH_ACK);
				}
#endif
				if (itype == INSERT_SENT) {
					sent_type s_type;
					if (data_seg->flags & TH_SYN || data_seg->flags & TH_FIN) {
						brIt->second->syn += !!(data_seg->flags & TH_SYN);
						brIt->second->fin += !!(data_seg->flags & TH_FIN);
						s_type = ST_RTR;
					}
					else if (data_seg->flags & TH_RST) {
						s_type = ST_RST;
						brIt->second->rst += !!(data_seg->flags & TH_RST);
					}
					else {
						s_type = ST_PURE_ACK;
#ifdef DEBUG
						if (debug_print) {
							indent_print("Neither SYN nor FIN!, increased acked_sent to %d\n", brIt->second->acked_sent);
						}
#endif
					}
					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, s_type);
				}
				else if (itype == INSERT_RECV) {
					// Set receied tstamp for SYN/FIN
					if (data_seg->flags & TH_SYN || data_seg->flags & TH_FIN) {
						brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					}
					if (!level) {
						brIt->second->packet_received_count++;
					}
				}
				else if (itype == INSERT_SOJOURN) {
#ifdef DEBUG
					throw std::logic_error("Sojourn not handled 3: in insertByteRange:"
						"seq: " + to_string(start_seq) +
						", end seq: " + to_string(end_seq) +
						", Type: " + to_string(itype)
						);
#endif
				}
			}
#ifdef DEBUG
			else {
				printf("WAS END, searched for start: %llu\n", std::min(start_seq -1, start_seq));
			}
#endif
			return true;
		}

		// The end_seq of the new range doesn't correspond to the end-seq of the entry in the map
		if (brIt->second->endSeq != end_seq) {
			if (itype == INSERT_RECV) {
				// The ack on the syn-ack
				if (end_seq == firstSeq +1) {
					brIt = ranges.find(start_seq -1);
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					assert(0 && "The ack on the syn-ack??\n");
					return true;
				}
			}

			//printf("brIt->second->endSeq: %llu\n", brIt->second->endSeq);
			//printf("end_seq: %llu\n", end_seq);
			// Spans multiple byte ranges
			if (brIt->second->endSeq < end_seq) {
#ifdef DEBUG
				if (debug_print) {
					indent_print("%s overlaps byte ranges:  %s\n", strByteRange(start_seq, end_seq).c_str(),
								 strByteRange(brIt->second->startSeq, brIt->second->endSeq).c_str());
					indent_print("Increase count of %s\n", strByteRange(brIt->second->startSeq, brIt->second->endSeq).c_str());
					indent_print("Setting is_rdb : %d\n", data_seg->is_rdb);
					indent_print("Setting retrans: %d\n", data_seg->retrans);
					indent_print("Is last: %d\n", std::end(ranges) == brIt );
					indent_print("It index: %ld, total count: %ld\n", std::distance(ranges.begin(), brIt), ranges.size());
				}
#endif
				if (itype == INSERT_SENT) {
					//assert("sent_count is 0!" && brIt->second->sent_count > 0);

					// The starting sequence number was already registered as a pure ack.
					if (brIt->second->byte_count == 0) {

						// We are at the last range in the map
						if (ranges.rbegin()->second == brIt->second) {
							// The last range in the map only had pure acks, so we hijack this and add the data to it
							brIt->second->endSeq = end_seq;
							brIt->second->updateByteCount();
							brIt->second->original_payload_size = brIt->second->byte_count;
							brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, ST_PKT);
							return true;
						}

						auto brItNext = std::next(brIt);
						if (brIt->second->endSeq != brItNext->second->startSeq) {
							// We have a gap in the ranges that we can fill either fully or partially.
							brIt->second->endSeq = min(brItNext->second->startSeq, end_seq);
							brIt->second->updateByteCount();
							brIt->second->original_payload_size = brIt->second->byte_count;
							brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, ST_PKT);
							if (brIt->second->endSeq < end_seq) {
								// The gap was filled, but more data remains to be added
								return insertByteRange(brIt->second->endSeq, end_seq, itype, data_seg, level +1);
							}
							else {
								// The segment filled the gap either fully or partially
								return true;
							}
						}
						else {
							// There is no gap, so add 1 byte to this range and add the rest recursively
							// An alternative would be to merge this range with the next
							brIt->second->endSeq = brIt->second->endSeq + 1;
							brIt->second->updateByteCount();
							//brIt->second->original_payload_size = brIt->second->byte_count;
							brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, ST_PKT);
							if (brIt->second->endSeq < end_seq) {
								return insertByteRange(brIt->second->endSeq, end_seq, itype, data_seg, level +1);
							}
							else {
								return true;
							}
						}
					}
					else {
						sent_type type = ST_NONE;
						if (!level) {
							type = data_seg->retrans ? ST_RTR : ST_PKT;
							if (data_seg->flags & TH_FIN) {
								brIt->second->fin += 1;
							}
						}
						brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, type);
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
				}
				else if (itype == INSERT_RECV) {
#ifdef DEBUG
					if (debug_print) {
						indent_print("data_received_count: %d\n", brIt->second->data_received_count);
					}
#endif
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
					if (!level) {
						brIt->second->packet_received_count++;
					}
#ifdef DEBUG
					if (debug_print) {
						indent_print("received_tstamp_tcp: %d\n", brIt->second->received_tstamp_tcp);
						indent_print("Conn: %s\n", conn->getConnKey().c_str());
						indent_print("Range: %s\n", STR_ABSOLUTE_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq));
					}
#endif
					assert(brIt->second->received_tstamp_tcp && "TEST\n");
				}
				else if (itype == INSERT_SOJOURN) {
					bool ret = brIt->second->addSegmentEnteredKernelTime(brIt->second->endSeq, data_seg->tstamp_pcap);
					if (!ret) {
						printf("SOJOURN DEBUG 3\n");
					}

					//indent_print("Sojourn recursive call3: ByteRange(%s): start_seq: %llu, end_seq: %llu\n",
					//			 STR_ABSOLUTE_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq), start_seq, end_seq);
					auto brItNext = brIt;
					if ((++brItNext) == ranges.end()) {
						// This is the last element, so cannot continue calling recursively.
						return false;
					}
				}

				if (level > RECURSION_LEVEL) {
					throw std::logic_error(strfmt("Recurse level too high: %d in insertByteRange: start seq: %llu, end seq: %llu, size: %llu, Type: %d\n",
												  RECURSION_LEVEL, start_seq, end_seq, end_seq - start_seq, itype));
				}
				// Recursive call to insert the remaining data
#ifdef DEBUG
				if (debug_print) {
					indent_print("Recursive call1: brIt->endseq: %llu, endseq: %llu\n", brIt->second->endSeq, end_seq);
					//indent_print("tstamp_tcp: %u\n", data_seg->tstamp_tcp);
				}
#endif
				return insertByteRange(brIt->second->endSeq, end_seq, itype, data_seg, level +1);
			}
			// Spans less than the range, split current range
			else {
				if (itype != INSERT_SOJOURN) {
					ByteRange *new_br = brIt->second->splitEnd(end_seq, brIt->second->endSeq);
#ifdef DEBUG
					if (debug_print) {
						indent_print("New range ends in the middle of existing\nByteRange(%s) [%llu]\n", STR_ABSOLUTE_SEQNUM_PAIR(brIt->second->startSeq, new_br->endSeq), end_seq);
						indent_print("Split Range into: (%s), (%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq),
									 STR_ABSOLUTE_SEQNUM_PAIR(new_br->startSeq, new_br->endSeq));
					}
#endif
					if (itype == INSERT_SENT) {
						sent_type type = ST_NONE;
						if (!level) {
							type = data_seg->retrans ? ST_RTR : ST_PKT;
							if (data_seg->flags & TH_FIN) {
								brIt->second->fin += 1;
							}
						}
						brIt->second->data_retrans_count += data_seg->retrans;
						brIt->second->rdb_count += data_seg->is_rdb;
						brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, type);
#ifdef DEBUG
						if (this_is_rdb_data) {
							assert(data_seg->retrans != 0 && "Should not be retrans!\n");
						}
#endif
					}
					else if (itype == INSERT_RECV) {
						brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
						if (!level) {
							brIt->second->packet_received_count++;
						}
					}
					ranges.insert(pair<seq64_t, ByteRange*>(new_br->startSeq, new_br));
				}
				else {// INSERT_SOJOURN - Do not split, only register sojourn timestamp
					bool ret = brIt->second->addSegmentEnteredKernelTime(end_seq, data_seg->tstamp_pcap);
					if (!ret) {
						printf("SOJOURN DEBUG 2\n");
					}
				}
			}
		}
		else {
			// The end_seq of the new range correspond to the end-seq of the entry in the map, so it's a duplicate
			if (itype == INSERT_SENT) {
				sent_type type = ST_NONE;
				if (!level) {
					type = data_seg->retrans ? ST_RTR : ST_PKT;
					if (data_seg->flags & TH_FIN) {
						brIt->second->fin += 1;
					}
				}
				brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_tcp_echo, data_seg->tstamp_pcap, this_is_rdb_data, type);
				brIt->second->data_retrans_count += data_seg->retrans;
				brIt->second->rdb_count += data_seg->is_rdb;

				if (data_seg->flags & TH_SYN) {
					brIt->second->syn += 1;
				}
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
			else if (itype == INSERT_RECV) {
				brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap, data_seg->in_sequence);
				if (!level) {
					brIt->second->packet_received_count++;
				}

#ifdef DEBUG
				if (debug_print) {
					printf("Setting received timestamp: %u\n", brIt->second->received_tstamp_tcp);
					printf("tstamps: %lu, rdb-stamps: %lu", brIt->second->tstamps_tcp.size(), brIt->second->rdb_tstamps_tcp.size());
				}
#endif
			}
			else if (itype == INSERT_SOJOURN) {
				bool ret = brIt->second->addSegmentEnteredKernelTime(end_seq, data_seg->tstamp_pcap);
				if (!ret) {
					//printf("SOJOURN DEBUG 1 start_seq: %ld, end_seq: %ld\n", start_seq, end_seq);
				}

			}
		}
	}
	return true;
}


/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAck(DataSeg *seg) {
	ByteRange* tmpRange;
	map<seq64_t, ByteRange*>::iterator it, it_end, prev;
	bool ret = false;
	seq64_t ack = seg->ack;
	it = ranges.begin();
	it_end = ranges.end();
	ack_count++;

	if (highestAckedByteRangeIt == ranges.end()) {
		it = ranges.begin();
	}
	else {
		it = highestAckedByteRangeIt;
	}

#ifdef DEBUG
	int debug_print = 0;
	//if (ack < 5000)
	//	debug_print = 1;

	if (debug_print) {
		printf("ProcessACK: %8llu  (%8llu), TSVal: %u, last acked start seq: %llu\n", get_print_seq(ack), ack, seg->tstamp_tcp,
		       get_print_seq(it->second->getStartSeq()));
	}
#endif

	/* All data from this ack has been acked before: return */
	if (ack < it->second->getStartSeq()) {
		if (DEBUGL_SENDER(3)) {
			cerr << "--------All data has been ACKed before - skipping--------" << endl;
			fprintf(stderr, "ProcessACK: %8llu  (%8llu), TSVal: %u, last acked start seq: %llu\n",
					get_print_seq(ack), ack, seg->tstamp_tcp, get_print_seq(it->second->getStartSeq()));
		}
		return true;
	}

	for (; it != it_end; it++) {
		tmpRange = it->second;

		if (DEBUGL_SENDER(3)) {
			cerr << "tmpRange - startSeq: " << get_print_seq(tmpRange->getStartSeq())
			     << " - endSeq: " << get_print_seq(tmpRange->getEndSeq()) << endl;
		}
		/* This ack covers this range, but not more: ack and return
		 1 -> Acked data range
		 2 -> ack on range with no data
		 */
		if (ack == tmpRange->getEndSeq() || (tmpRange->getNumBytes() == 0 && (ack - 1) == tmpRange->getEndSeq())) {
#ifdef DEBUG
			if (DEBUGL_SENDER(3))
				fprintf(stderr, "  Covers just this Range(%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(tmpRange->getStartSeq(), tmpRange->getEndSeq()));
#endif
			if (!tmpRange->isAcked()) {
				tmpRange->tcp_window = seg->window;
				if (tmpRange->getNumBytes() == 0) {
					// Special case. This is probably an ACK at the end of the stream.
					// If timestamps enabled, use TSval/TSecr to verify that the Range
					// does not in fact ACK the ack we are registering
					if (tmpRange->tstamps_tcp.size()) {
						if (tmpRange->tstamps_tcp[0].second == seg->tstamp_tcp) {
							// This ByteRange is actually an ACK on the incomming ACK, therefore
							// no ACK time should be registered for this ByteRange
						}
						else {
							tmpRange->insertAckTime(&seg->tstamp_pcap);
						}
					}
				}
				else {
					tmpRange->insertAckTime(&seg->tstamp_pcap);
				}
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
		if (ack > tmpRange->getEndSeq()) {

#ifdef DEBUG
			if (DEBUGL_SENDER(3) && debug_print)
				printf("  Covers more than Range(%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(tmpRange->getStartSeq(), tmpRange->getEndSeq()));
#endif
			if (timercmp(&seg->tstamp_pcap, &(tmpRange->sent_tstamp_pcap[0].first), <)) {
				if (DEBUGL_SENDER(1)) {
					fprintf(stderr, "ACK TIME IS EARLIER THAN SEND TIME!\n");
					warn_with_file_and_linenum(__FILE__, __LINE__);
				}
				return false;
			}

			if (!tmpRange->isAcked()) {
				tmpRange->insertAckTime(&seg->tstamp_pcap);
#ifdef DEBUG
				//if (tmpRange->getNumBytes() == 0) {
				//	fprintf(stderr, "Insert acktime 2 on %s\n", tmpRange->str().c_str());
				//}
#endif
				ret = true;
			}
			highestAckedByteRangeIt = it;
			continue;
		}

		/* ACK covers only part of this range: split range and return */
		if (ack > tmpRange->getStartSeq() && ack < tmpRange->getEndSeq()) {
#ifdef DEBUG
			if (DEBUGL_SENDER(1) && debug_print) {
				printf("  Covers parts of  Range(%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(tmpRange->getStartSeq(), tmpRange->getEndSeq()));
			}
#endif
			ByteRange *new_br = tmpRange->splitEnd(ack, tmpRange->endSeq);
			tmpRange->insertAckTime(&seg->tstamp_pcap);
#ifdef DEBUG
			if (tmpRange->getNumBytes() == 0) {
				printf("Insert acktime 3 on %s\n", tmpRange->str().c_str());
			}
#endif
			tmpRange->tcp_window = seg->window;
			tmpRange->ack_count++;

			// Second part of range: insert after tmpRange (tmpRange)
			highestAckedByteRangeIt = ranges.insert(std::pair<seq64_t, ByteRange*>(new_br->getStartSeq(), new_br)).first;
			return true;
		}

		// This is when receiver sends a FIN, the ack seq is then not incremented
		if ((seg->flags & TH_FIN) && ack == (tmpRange->getEndSeq())) {
			tmpRange->ack_count++;
			highestAckedByteRangeIt = it;
			return true;
		}
		prev = it;
		assert(it != ranges.begin() && "We are at the first range. Will crash!\n");

		prev--;
		// ACK incremented one extra after receiving FIN
		if ((ack-1) == prev->second->getEndSeq()) {
			// There is a gap of 1 byte
			// This can be caused by a FIN being sent, and the seq num being increased
			// Even if no data was sent
			do {
				if (prev->second->fin) {
					prev->second->ack_count++;
					return true;
				}
				if (prev->second->packet_sent_count == prev->second->getDataSentCount())
					break;
				prev--;
			} while (true);
		}

		// ACK on old data, just ignore
		if (ack < tmpRange->getEndSeq()) {
			do {
				//printf("ack: %llu, prev->end: %llu\n", ack, prev->second->getEndSeq());
				if (ack == prev->second->getEndSeq()) {
					prev->second->ack_count++;
					return true;
				}

				if (ack > prev->second->getEndSeq()) {
					//if (ack == prev->second->getStartSeq())
						//printf("ack is bigger: %llu, prev->end: %llu\n", ack, prev->second->getEndSeq());
					return true;
				}
			} while (prev-- != ranges.begin());

			return false;
		}

		/* If we get here, something's gone wrong */
		if (ack == tmpRange->getStartSeq()) {
			// This happens only if the dump does not contain the previous data range.
			// Probably caused by starting tcpdump in the middle of a stream
			return false;
		}

		fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
		fprintf(stderr, "RangeManager::processAck: Possible error when processing ack: %llu (%llu)\n", get_print_seq(ack), ack);
		fprintf(stderr, "Range(%s) (%s)\n",
				STR_ABSOLUTE_SEQNUM_PAIR(tmpRange->getStartSeq(), tmpRange->getEndSeq()), STR_SEQNUM_PAIR(tmpRange->getStartSeq(), tmpRange->getEndSeq()));
		ByteRange *tmp = ranges.begin()->second;
		fprintf(stderr, "First Range(%s) (%s)\n", STR_ABSOLUTE_SEQNUM_PAIR(tmp->getStartSeq(), tmp->getEndSeq()), STR_SEQNUM_PAIR(tmp->getStartSeq(), tmp->getEndSeq()));

		printf("tmpRange FIN: %d\n", prev->second->fin);
		warn_with_file_and_linenum(__FILE__, __LINE__);
		break;
	}
	if (!ret) {
		fprintf(stderr, "Failed to find packet for ack: %llu on connection: %s\n", ack, conn->getConnKey().c_str());
	}

	return ret;
	}


void RangeManager::genStats(PacketsStats *bs) {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	long latency;
	uint32_t tmp_byte_count;
	bs->latency.min = bs->packet_length.min = bs->itt.min = (numeric_limits<ullint_t>::max)();
	ulong dupack_count;
	SegmentStats psTmp;

	for (; it != it_end; it++) {
		// Skip if invalid (negative) latency
		tmp_byte_count = static_cast<uint32_t>(it->second->getOrinalPayloadSize());

		if (tmp_byte_count) {
			bs->packet_length.add(static_cast<ullint_t>(tmp_byte_count));
			for (int i = 0; i < it->second->getNumRetrans(); i++) {
				bs->packet_length.add(static_cast<ullint_t>(tmp_byte_count));
			}
		}

		for (size_t i = 0; i < it->second->sent_tstamp_pcap.size(); i++) {
			if (it->second->sent_tstamp_pcap[i].second) {
				if (it->second->sent_tstamp_pcap[i].second == ST_PKT) {
					assert(it->second->sent_tstamp_pcap[i].second == ST_PKT);
					psTmp = SegmentStats(ST_PKT, conn->getConnKey(), TV_TO_MICSEC(it->second->sent_tstamp_pcap[i].first), static_cast<uint16_t>(tmp_byte_count));
					psTmp.sojourn_times = it->second->getSojournTimes();
					psTmp.ack_latency_usec = static_cast<int>(it->second->getSendAckTimeDiff(this));
				}
				else if (it->second->sent_tstamp_pcap[i].second == ST_RTR) {
					// This is a retransmit
					// In case a collapsed retrans packet spans multiple segments, check if next range has retrans data
					// that is not a retrans packet in itself
					uint32_t tmp_byte_count2 = tmp_byte_count;
					map<seq64_t, ByteRange*>::iterator it_tmp = it;
					if (++it_tmp != it_end) {
						if (it_tmp->second->packet_retrans_count < it_tmp->second->data_retrans_count) {
							tmp_byte_count2 += it_tmp->second->data_retrans_count * it_tmp->second->byte_count;
						}
					}
					psTmp = SegmentStats(ST_RTR, conn->getConnKey(), TV_TO_MICSEC(it->second->sent_tstamp_pcap[i].first), tmp_byte_count2);
					//printf("RETRANS: %llu -> %llu\n", tmp_byte_count, tmp_byte_count2);
				}
				else if (it->second->sent_tstamp_pcap[i].second == ST_PURE_ACK) {
					psTmp = SegmentStats(ST_PURE_ACK, conn->getConnKey(), TV_TO_MICSEC(it->second->sent_tstamp_pcap[i].first), 0);
				}
				else if (it->second->sent_tstamp_pcap[i].second == ST_RST) {
					psTmp = SegmentStats(ST_RST, conn->getConnKey(), TV_TO_MICSEC(it->second->sent_tstamp_pcap[i].first), 0);
				}
				bs->addPacketStats(psTmp);
			}
		}

		dupack_count = it->second->dupack_count;

		// Make sure the vector has enough space
		for (ulong i = bs->dupacks.size(); i < dupack_count; i++) {
			bs->dupacks.push_back(0);
		}

		for (ulong i = 0; i < dupack_count; i++) {
			bs->dupacks[i]++;
		}

		if ((latency = it->second->getSendAckTimeDiff(this))) {
			bs->latency.add(static_cast<ullint_t>(latency));
		} else {
			if (!it->second->isAcked())
				continue;
		}

		ulong retrans = static_cast<ulong>(it->second->getNumRetrans());
		// Make sure the vector has enough space
		for (ulong i = bs->retrans.size(); i < retrans; i++) {
			bs->retrans.push_back(0);
		}
		for (ulong i = 0; i < retrans; i++) {
			bs->retrans[i]++;
		}
	}

	std::sort(bs->packet_stats.begin(), bs->packet_stats.end());


	PacketStats prev = bs->packet_stats[0];
	long itt;
	for (size_t i = 1; i < bs->packet_stats.size(); i++) {
		itt = bs->packet_stats[i].send_time_us - prev.send_time_us;
		bs->itt.add((ullint_t) itt);
		bs->packet_stats[i].itt_usec = (int) itt;
		prev = bs->packet_stats[i];
	}

    bs->latency.makeStats();
    bs->packet_length.makeStats();
    bs->itt.makeStats();
}

/* Check that every byte from firstSeq to lastSeq is present.
   Print number of ranges.
   Print number of sent bytes (payload).
   State if send-times occur: how many.
   State if ack-times occur: how many. */
void RangeManager::validateContent() {
	int numAckTimes = 0;
	int numSendTimes = 0;
	seq64_t tmpEndSeq = 0;

	map<seq64_t, ByteRange*>::iterator first, it, it_end, prev;
	first = it = ranges.begin();
	it_end = ranges.end();
	prev = it_end;

	/* FirstRange.startSeq == firstSeq
	   LastRange.endSeq == lastSeq
	   every packet in between are aligned */
	if (it->second->getStartSeq() != 0) {
		printf("firstSeq: %u, StartSeq: %llu\n", firstSeq, it->second->getStartSeq());
		printf("RangeManager::validateContent: firstSeq != StartSeq (%llu != %llu)\n", get_print_seq(it->second->getStartSeq()), get_print_seq(firstSeq));
		printf("First range (%llu, %llu)\n", get_print_seq(it->second->getStartSeq()), get_print_seq(it->second->getEndSeq()));
		printf("Conn: %s\n", conn->getConnKey().c_str());
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	//printf("ranges.rbegin()->second->getEndSeq(): %llu\n", ranges.rbegin()->second->getEndSeq());
	//printf("lastSeq: %llu\n", lastSeq);
	//printf("ranges.rbegin()->second->getEndSeq(): %llu\n", ranges.rbegin()->second->getEndSeq());
	//printf("lastSeq - 1: %llu\n", lastSeq - 1);
	if (!(ranges.rbegin()->second->getEndSeq() <= lastSeq && ranges.rbegin()->second->getEndSeq() >= (lastSeq - 1))) {
		fprintf(stderr, "RangeManager::validateContent: lastSeq unaligned! lastSeq: %llu, EndSeq: %llu\n", get_print_seq(lastSeq), get_print_seq(ranges.rbegin()->second->getEndSeq()));
		fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	if (conn->totBytesSent != (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent)) {
		ullint_t totBytesSentCalculated = conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent;
		fprintf(stderr, "conn->totBytesSent(%9llu) != %-9llu (Diff: %llu) (totNewDataSent(%llu) + totRDBBytesSent(%llu) + totRetransBytesSent(%llu)) \n",
				conn->totBytesSent, totBytesSentCalculated, totBytesSentCalculated - conn->totBytesSent,
				conn->totNewDataSent, conn->totRDBBytesSent, conn->totRetransBytesSent);
		fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
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
			if (prev->second->endSeq != it->second->startSeq && prev->second->startSeq != prev->second->endSeq) {
				// Allow gap at the end with FIN packets
				if (!prev->second->fin && it->second->byte_count) {
					fprintf(stderr, "Range not continuous!\n Gap in (%s) - (%s)\n",
						   STR_SEQNUM_PAIR(prev->second->startSeq, prev->second->endSeq), STR_SEQNUM_PAIR(it->second->startSeq, it->second->endSeq));
					fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
				}
			}
		}
#endif

		if (it->second->getStartSeq() == tmpEndSeq) {
			tmpEndSeq = it->second->getEndSeq();
		} else {
			// They are not equal when previous has no payload
			// ACKS
			if (prev == it_end || prev->second->getNumBytes() == 0 || it->second->getNumBytes() == 0) {
				tmpEndSeq = it->second->getEndSeq();
			}
			else {
				fprintf(stderr, "PREV NUMBYTES: %d\n", prev->second->getNumBytes());
				fprintf(stderr, "CURR NUMBYTES: %d\n", it->second->getNumBytes());

				cerr << "RangeManager::validateContent: Byte-stream in ranges not continuous. Exiting." << endl;
				fprintf(stderr, "payload_len: %d\n", it->second->getNumBytes());

				fprintf(stderr, "Prev Range (%s) Len: %u\n", STR_ABSOLUTE_SEQNUM_PAIR(prev->second->getStartSeq(), prev->second->getEndSeq()),
					   prev->second->getNumBytes());
				fprintf(stderr, "Curr Range (%s) Len: %u\n", STR_ABSOLUTE_SEQNUM_PAIR(it->second->getStartSeq(), it->second->getEndSeq()),
					   it->second->getNumBytes());
				cerr << "tmpEndSeq           : " << get_print_seq(tmpEndSeq) << endl;
				cerr << "Conn KEY           : " << conn->getConnKey() << endl;
				warn_with_file_and_linenum(__FILE__, __LINE__);
				tmpEndSeq = it->second->getEndSeq();
			}
		}

		if (it->second->getSendTime())
			numSendTimes++;
		if (it->second->getAckTime())
			numAckTimes++;

		prev = it;
	}

	if (DEBUGL_SENDER(2)) {
		cerr << "First seq: " << firstSeq << " Last seq: " <<  lastSeq << endl;
		cerr << "Number of ranges: " << ranges.size() << endl;
		cerr << "Number of bytes: " << lastSeq - firstSeq << endl;
		cerr << "numSendTimes: " << numSendTimes << endl;
		cerr << "numAckTimes: " << numAckTimes << endl;
		cerr << "Is first range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Is last range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Last range: startSeq: " << get_print_seq(ranges.begin()->second->getStartSeq())
			 << " - endSeq: " << get_print_seq(ranges.begin()->second->getEndSeq()) << endl;
	}
}

bool negSojTime(ByteRange *br) {
	vector< pair<int, int> > sojourn_times = br->getSojournTimes();
	for (ulong i = 0; i < sojourn_times.size(); i++) {
		int sojourn_time_us = sojourn_times[i].second;
		if (sojourn_time_us < 0)
			return true;
	}
	return false;
}

int seqWithPrintRange(seq64_t start, seq64_t end, size_t &print_packet_ranges_index) {
	while (end > GlobOpts::print_packets_pairs[print_packet_ranges_index].second) {
		// We are at the last range so we quit printing
		if (GlobOpts::print_packets_pairs.size() == (print_packet_ranges_index + 1)) {
			return -1;
		}
		print_packet_ranges_index++;
		cout << "---------------------------------------------------------" << endl;
	}
	if (start < GlobOpts::print_packets_pairs[print_packet_ranges_index].first)
		return 0;
	return 1;
}

/*
  Print a list of all the registered ranges.
*/
void RangeManager::printPacketDetails() {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	int seq_char_len = (int) to_string(get_print_seq(ranges.rbegin()->second->endSeq)).length();
	int rel_seq_char_len = (int) to_string(ranges.rbegin()->second->endSeq).length();
	int range_paylad_len = (int) to_string(analysed_max_range_payload).length();

	cout << endl << "Packet details for conn: " << conn->getConnKey() << endl;

	bool print_packet_ranges = GlobOpts::print_packets_pairs.size();
	size_t print_packet_ranges_index = 0;

	int range_count = 0;
	for (; it != it_end; it++) {
		range_count++;

		if (it->second->sojourn_time)
			continue;

		if (print_packet_ranges) {
			int ret = seqWithPrintRange(it->second->startSeq, it->second->endSeq, print_packet_ranges_index);
			if (ret == -1)
				goto endprint;
			else if (!ret)
				continue;
		}

		printf("R(%*u, %*u):", range_paylad_len, it->second->getNumBytes(), range_paylad_len, it->second->original_payload_size);
		if (DEBUGL_SENDER(1)) {
			printf(" %-*u - %-*u: (%-*llu - %-*llu):",
				   seq_char_len, absolute_seq(it->second->startSeq), seq_char_len, absolute_seq(it->second->endSeq),
				   rel_seq_char_len, it->second->startSeq, rel_seq_char_len, it->second->endSeq);
		}
		else {
			printf(" %-*llu - %-*llu:", seq_char_len, get_print_seq(it->second->startSeq), seq_char_len, get_print_seq(it->second->endSeq));
		}

		printf(" pkt[snt:%d rtr:%d acks:%d rcv:%d]", it->second->packet_sent_count,
			   it->second->packet_retrans_count, it->second->acked_sent, it->second->packet_received_count);

		printf(" dta[snt:%d rcv:%d rtr:%d]", it->second->getDataSentCount(), it->second->getDataReceivedCount(),
			   it->second->data_retrans_count);

		if (GlobOpts::verbose > 1) {
			if (analysed_rdb_packet_count)
				printf(", rdb-cnt:%d", it->second->rdb_count);

			if (GlobOpts::withRecv) {
				printf(", RCV: %s", received_type_str[it->second->recv_type]);
			}

			if (analysed_rdb_packet_count)
				printf(", rdb-miss: %-3d rdb-hit: %-3d", it->second->rdb_miss_count, it->second->rdb_hit_count);
		}

		printf(", ACKtime: %.1f", (double) it->second->getSendAckTimeDiff(this) / 1000.0);

		if (not GlobOpts::sojourn_time_file.empty()) {
			if (it->second->sojourn_time) {
				int sojourn_time_us;
				vector< pair<int, int> > sojourn_times = it->second->getSojournTimes();
				printf(", SOJ(%ld):", sojourn_times.size());
				for (ulong i = 0; i < sojourn_times.size(); i++) {
					sojourn_time_us = sojourn_times[i].second;
					printf("%d, ", sojourn_time_us);
					if (GlobOpts::verbose <= 2 && i == 2)
						break;
				}
			}
		}

#ifdef DEBUG
		int psent = 0;
		//psent += (it->second->syn || it->second->fin || /*it->second->rst ||*/ it->second->byte_count);
		psent += (it->second->syn + it->second->rst);
		//psent += (it->second->syn || it->second->rst || (it->second->byte_count && it->second->packet_sent_count));
		psent += (!it->second->byte_count ? it->second->fin : 0);
		psent += !!it->second->byte_count;
		psent += it->second->data_retrans_count;
		//psent += it->second->packet_retrans_count;
		psent += it->second->acked_sent; // Count pure acks

		if (psent != (it->second->packet_sent_count + it->second->packet_retrans_count + it->second->acked_sent)) {
			colored_printf(YELLOW, " SENT MISMATCH packet_sent_count: %u != %u (syn: %u, rst: %u, fin: %u, byte_count: %u)", psent,
						   it->second->packet_sent_count + it->second->packet_retrans_count + it->second->acked_sent,
						   it->second->syn, it->second->rst, it->second->fin && !it->second->byte_count, it->second->byte_count);
		}
#endif

		if (GlobOpts::verbose > 1) {
			if (GlobOpts::withRecv) {
				printf(" RecvDiff: %4ld ", (it->second->getRecvDiff() - lowestRecvDiff));
			}
			if (GlobOpts::verbose) {
				printf(" (%4ld)", it->second->getSendAckTimeDiff(this) - (it->second->getRecvDiff() - lowestRecvDiff));
			}
		}

		if (it->second->syn || it->second->rst || it->second->fin) {
			if (it->second->syn)
				colored_printf(YELLOW, " SYN(%d)", it->second->syn);
			if (it->second->rst)
				colored_printf(YELLOW, " RST(%d)", it->second->rst);
			if (it->second->fin)
				colored_printf(YELLOW, " FIN(%d)", it->second->fin);
		}

		if (GlobOpts::withRecv) {
			if (it->second->getDataSentCount() > it->second->getDataReceivedCount()) {
				printf("   LOST %d times", it->second->getDataSentCount() - it->second->getDataReceivedCount());
			}
		}

		if (!it->second->data_retrans_count && !it->second->rdb_count && (it->second->rdb_miss_count || it->second->rdb_hit_count)) {
			printf(" FAIL (RDB hit/miss calculalation has failed)!");
		}
		printf("\n");
	}
endprint:
	;
}


void RangeManager::calculateRetransAndRDBStats() {
	calculateRealLoss(analyse_range_start, analyse_range_end);
}

void RangeManager::calculateRealLoss(map<seq64_t, ByteRange*>::iterator brIt, map<seq64_t, ByteRange*>::iterator brIt_end) {
	ByteRange *prev = NULL;
	ulong index = 0;
	int lost_tmp = 0;
	int match_fails_before_end = 0;
	int match_fails_at_end = 0;
	int lost_packets = 0;
	bool prev_pack_lost = false;
	double loss_and_end_limit = 0.01;
	int p_retr_count = 0;
	int ranges_with_data = 0;
	bool print_timestamp_mismatch_warn_end = GlobOpts::print_timestamp_mismatch_warn;

	for (; brIt != brIt_end; brIt++) {
		prev = brIt->second;
		index++;

		if (GlobOpts::withRecv) {
			bool ret = brIt->second->matchReceivedType();
			if (ret == false) {
				if (index < (ranges.size() * (1 - loss_and_end_limit))) {
					match_fails_before_end++;
					if (DEBUGL_RECEIVER(1) && GlobOpts::print_timestamp_mismatch_warn) {
						colored_printf(YELLOW, "Failed to match %s (%s) (index: %llu) on %s\n",
									   STR_ABSOLUTE_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq),
									   STR_SEQNUM_PAIR(brIt->second->startSeq, brIt->second->endSeq), index, conn->getConnKey().c_str());
						brIt->second->printTstampsTcp();
						if (GlobOpts::debugLevel == 1) {
							colored_printf(YELLOW, "Enable debug=2 to show further header mismatch warnings.\n");
							GlobOpts::print_timestamp_mismatch_warn = false;
						}
					}
				}
				else
					match_fails_at_end++;
			}
		}

		int rdb_count = brIt->second->rdb_count;
		if (rdb_count && brIt->second->recv_type == RDB) {
			rdb_count -= 1; // Remove the successfull rdb transfer
			brIt->second->rdb_hit_count = 1;
			rdb_byte_hits += brIt->second->byte_count;
		}

		if (brIt->second->recv_type == RDB) {
			rdb_packet_hits++;
		}

		p_retr_count += brIt->second->packet_retrans_count;

		rdb_byte_miss += brIt->second->rdb_miss_count * brIt->second->byte_count;

		analysed_sent_ranges_count += brIt->second->getDataSentCount();
		analysed_redundant_bytes += brIt->second->byte_count * (brIt->second->data_retrans_count + brIt->second->rdb_count);

		if (brIt->second->byte_count) {
			// Always count 1 for a ByteRange, even though the orignal sent data might have been segmented on the wire.
			analysed_data_packet_count += 1 + brIt->second->data_retrans_count;
			ranges_with_data++;
		}
		else
			analysed_retr_no_payload_packet_count += brIt->second->packet_retrans_count;

		//printf("sent_count: %d, retrans_count: %d\n", brIt->second->getDataSentCount(), brIt->second->retrans_count);
		//assert("FAIL" && (1 + brIt->second->packet_retrans_count == brIt->second->getDataSentCount()));

		analysed_syn_count += brIt->second->syn;
		analysed_fin_count += brIt->second->fin;
		analysed_rst_count += brIt->second->rst;

		analysed_pure_acks_count += brIt->second->acked_sent;
		analysed_rdb_packet_count += brIt->second->original_packet_is_rdb;
		analysed_bytes_sent += brIt->second->getDataSentCount() * brIt->second->byte_count;
		analysed_bytes_sent_unique += brIt->second->byte_count;

		// analysed_packet_sent_count is the number of (adjusted) packets sent, which will be greater if segmentation offloading is enabled.
		// analysed_packet_sent_count_in_dump is the number of packets found in the dump (same as wireshark and tcptrace)

		// We count 1 for all ranges with data and where syn or fin is set
		//analysed_packet_sent_count += (brIt->second->syn || brIt->second->fin || /*brIt->second->rst ||*/ brIt->second->byte_count);
		//analysed_packet_sent_count += (brIt->second->syn + brIt->second->fin) + (!!brIt->second->byte_count));

/*
		printf("brIt->second->syn + brIt->second->rst: %d\n", brIt->second->syn + brIt->second->rst);
		printf("brIt->second->fin && !brIt->second->byte_count: %d\n", !brIt->second->byte_count ? brIt->second->fin : 0);
		printf("!!brIt->second->byte_count: %d\n", !!brIt->second->byte_count);
		printf("brIt->second->data_retrans_count: %d\n", brIt->second->data_retrans_count);
		printf("brIt->second->acked_sent: %d\n", brIt->second->acked_sent);
*/

		analysed_packet_sent_count += (brIt->second->syn + brIt->second->rst);
		// Count packet sent for FIN only if no data was sent
		analysed_packet_sent_count += !brIt->second->byte_count ? brIt->second->fin : 0;

		analysed_packet_sent_count += !!brIt->second->byte_count;
		analysed_max_range_payload = max(analysed_max_range_payload, brIt->second->original_payload_size);

		//analysed_packet_sent_count += brIt->second->packet_retrans_count;
		analysed_packet_sent_count += brIt->second->data_retrans_count;
		analysed_packet_sent_count += brIt->second->acked_sent; // Count pure acks
		analysed_retr_packet_count += brIt->second->packet_retrans_count;

		analysed_bytes_retransmitted += brIt->second->data_retrans_count * brIt->second->byte_count;
		analysed_ack_count += brIt->second->ack_count;

		// This should be the number of packets found in the dump (same as wireshark and tcptrace)
		analysed_packet_sent_count_in_dump += brIt->second->packet_sent_count + brIt->second->packet_retrans_count + brIt->second->acked_sent;

		// This should be the number of packets found in the dump (same as wireshark and tcptrace)
		analysed_packet_received_count += brIt->second->packet_received_count;

		if (GlobOpts::withRecv) {
			if (brIt->second->getDataSentCount() != brIt->second->getDataReceivedCount()) {
				analysed_lost_ranges_count += (brIt->second->getDataSentCount() - brIt->second->getDataReceivedCount());
				analysed_lost_bytes += (brIt->second->getDataSentCount() - brIt->second->getDataReceivedCount()) * brIt->second->byte_count;
				ulong lost = (brIt->second->getDataSentCount() - brIt->second->getDataReceivedCount());

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
		}

		if (brIt->second->getDataSentCount() > 1)
			lost_tmp += brIt->second->getDataSentCount() - 1;
		else {
			lost_tmp = 0;
		}
	}

	rdb_packet_misses = analysed_rdb_packet_count - rdb_packet_hits;

#ifdef DEBUG
	//printf("Ranges count: %llu\n", ranges.size());
	//printf("ranges_with_data: %d\n", ranges_with_data);

//	printf("analysed_packet_sent_count: %d\n", analysed_packet_sent_count);
#endif

	if (DEBUGL_RECEIVER(1) && print_timestamp_mismatch_warn_end) {
		if (match_fails_before_end) {
			colored_printf(RED, "%s : Failed to find timestamp for %d out of %ld packets. ", conn->getConnKey().c_str(), match_fails_before_end, ranges.size());
			colored_printf(RED, "These packest were before the %f%% limit (%d) from the end (%llu), and might be caused by packets being dropped from tcpdump\n",
						   (1 - loss_and_end_limit), (int) (ranges.size() * (1 - loss_and_end_limit)), ranges.size());
		}
#ifndef DEBUG
		if (match_fails_at_end)
			printf("%s : Failed to find timestamp for %d out of %ld packets. These packets were at the end of the stream" \
				   ", so presumable they were just not caught by tcpdump.\n", conn->getConnKey().c_str(), match_fails_at_end, ranges.size());
#endif
	}
}

ByteRange* RangeManager::getHighestAcked() {
	if (highestAckedByteRangeIt == ranges.end())
		return NULL;
	return highestAckedByteRangeIt->second;
}

/*
   Returns duration of connection (in seconds)
*/
double RangeManager::getDuration() {
	map<seq64_t, ByteRange*>::iterator brIt_end = ranges.end();
	brIt_end--;
	return getDuration(brIt_end->second);
}

inline double RangeManager::getDuration(ByteRange *brLast) {
	return getTimeInterval(ranges.begin()->second, brLast);
}

/* Returns the difference between the start and end
   range in seconds */
double getTimeInterval(ByteRange *start, ByteRange *end) {
	timeval start_tv, current, tv;
	double time;
	start_tv = *(start->getSendTime());
	current = *(end->getSendTime());
	timersub(&current, &start_tv, &tv);
	time = (tv.tv_sec * 1000 + (tv.tv_usec / 1000)) / 1000.0;
	return time;
}


void RangeManager::calculateLatencyVariation() {
	registerRecvDiffs();
	calculateClockDrift();
	doDriftCompensation();
}


void RangeManager::registerRecvDiffs() {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	timeval *last_app_layer_tstamp = NULL;

	for (; it != it_end; it++) {
		if (!it->second->getDataReceivedCount()) {
			continue;
		}

		if (!GlobOpts::transport) {
			if (it->second->app_layer_latency_tstamp)
				last_app_layer_tstamp = &it->second->received_tstamp_pcap;
		}

		/* Calculate diff and check for lowest value */
		it->second->matchReceivedType();
		it->second->calculateRecvDiff(last_app_layer_tstamp);
	}

	if (DEBUGL_SENDER(3)) {
		cerr << "SendTime: " << it->second->getSendTime()->tv_sec << "."
			 << it->second->getSendTime()->tv_usec << endl;
		cerr << "RecvTime: ";
		if (it->second->getRecvTime() != NULL)
			cerr << it->second->getRecvTime()->tv_sec;
		cerr << endl;
	}
}


/*
  This code should be looked at regarding type conversions (double -> long)!
*/
void RangeManager::doDriftCompensation() {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	for (; it != it_end; it++) {
		double diff = (double) it->second->getRecvDiff();
		/* Compensate for drift */
		if (diff > 0) {
			//printf("(%s) diff: %g", STR_ABSOLUTE_SEQNUM_PAIR(it->second->getStartSeq(), it->second->getEndSeq()), diff);
			diff -= ((drift * getDuration(it->second)));
			it->second->setRecvDiff((long) diff);
			//printf(" -= (%g * %g) = %g -> %g \n", drift, getDuration(it->second), (drift * getDuration(it->second)), diff);
			if (diff < lowestRecvDiff) {
				lowestRecvDiff = (long) diff;
			}
		}
	}
}

/* Calculate clock drift on CDF */
int RangeManager::calculateClockDrift() {
	map<seq64_t, ByteRange*>::iterator startIt, startDriftRange;
	map<seq64_t, ByteRange*>::reverse_iterator endIt, endDriftRange;
	long minDiffStart = std::numeric_limits<long>::max();
	long minDiffEnd = std::numeric_limits<long>::max();
	timeval minTimeStart, minTimeEnd, tv;
	double durationSec, tmpDrift;
	timerclear(&minTimeStart);
	timerclear(&minTimeEnd);

	startIt = ranges.begin();

	const uint64_t n = std::min(200UL, ranges.size() / 2);

	for (uint64_t i = 0; i < n; i++) {
		if (startIt->second->getRecvDiff() < minDiffStart) {
			minDiffStart = startIt->second->getRecvDiff();
			minTimeStart = *(startIt->second->getSendTime());
			startDriftRange = startIt;
		}
		startIt++;
	}

	endIt = ranges.rbegin();
	for (uint64_t i = 0; i < n; i++) {
		// RecvDiff == 0 means the diff was not calculated
		if (endIt->second->getRecvDiff() < minDiffEnd && endIt->second->getRecvDiff() != 0) {
			minDiffEnd = endIt->second->getRecvDiff();
			minTimeEnd = *(endIt->second->getSendTime());
			endDriftRange = endIt;
		}
		endIt++;
	}

	if (!timerisset(&minTimeEnd) || !timerisset(&minTimeStart)) {
		fprintf(stderr, "Timevals have not been populated! minTimeStart is zero: %s, minTimeEnd is zero: %s\n",
				!timerisset(&minTimeStart) ? "Yes" : "No", !timerisset(&minTimeEnd) ? "Yes" : "No");
		warn_with_file_and_linenum(__FILE__, __LINE__);
		drift = 0;
		return 1;
	}

	/* Get time interval between values */
	timersub(&minTimeEnd, &minTimeStart, &tv);
	durationSec = tv.tv_sec + tv.tv_usec / 10000000;
	tmpDrift = (double) (minDiffEnd - minDiffStart) / durationSec;

	if (DEBUGL_SENDER(4)) {
		printf("Using start diff of range: %s\n", STR_ABSOLUTE_SEQNUM_PAIR(startDriftRange->second->getStartSeq(), startDriftRange->second->getEndSeq()));
		printf("Using end   diff of range: %s\n", STR_ABSOLUTE_SEQNUM_PAIR(endDriftRange->second->getStartSeq(), endDriftRange->second->getEndSeq()));

		printf("startMin: %lu\n", minDiffStart);
		printf("startTime: %lu.%lu\n", (ulong) minTimeStart.tv_sec, (ulong) minTimeStart.tv_usec);
		printf("endMin: %lu\n", minDiffEnd);
		printf("endTime: %lu.%lu\n", (ulong) minTimeEnd.tv_sec, (ulong) minTimeEnd.tv_usec);
		printf("DurationSec: %g\n", durationSec);
		printf("Clock drift: %g ms/s\n", tmpDrift);
	}
	drift = tmpDrift;
	return 0;
}

void RangeManager::makeByteLatencyVariationCDF() {
	map<seq64_t, ByteRange*>::iterator it, it_end;
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
	}
	GlobStats::totNumBytes += getNumBytes();
}


void RangeManager::writeSentTimesAndQueueingDelayVariance(const int64_t first_tstamp, vector<csv::ofstream*> streams) {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;
	string connKey = conn->getConnKey();

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff() - lowestRecvDiff;
		int64_t ts = TV_TO_MS(it->second->sent_tstamp_pcap[it->second->send_tcp_stamp_recv_index].first);

		//assert(diff >= 0 && "Negative diff, this shouldn't happen!");
		if (diff >= 0) {
			LatencyItem lat(static_cast<int>(ts - first_tstamp), (int) diff, connKey);

			for (csv::ofstream* stream : streams)
				*stream << lat << NEWLINE;
		}
	}
}

void RangeManager::writeByteLatencyVariationCDF(ofstream *stream) {
	map<const long, int>::iterator nit, nit_end;
	double cdfSum = 0;
	char print_buf[300];
	nit = byteLatencyVariationCDFValues.begin();
	nit_end = byteLatencyVariationCDFValues.end();

	*stream << "#------ Drift : " << drift << "ms/s ------" << endl;
	*stream << "#Relative delay      Percentage" << endl;
	for (; nit != nit_end; nit++) {
		cdfSum += (double)(*nit).second / getNumBytes();
		sprintf(print_buf, "time: %10ld    CDF: %.10f", (*nit).first, cdfSum);
		*stream << print_buf << endl;
	}
}


static inline uint64_t intervalIdx(const timeval& ts, int64_t first_tstamp) {
	long relative_ts = TV_TO_MS(ts) - first_tstamp;
	return (uint64_t) relative_ts / GlobOpts::lossAggrMs;
}

void RangeManager::calculateLossGroupedByInterval(const int64_t first_tstamp, vector<LossInterval>& all_loss, vector<LossInterval>& loss) {
	assert(GlobOpts::withRecv && "Writing loss grouped by interval requires receiver trace");

	vector<pair<uint32_t, timeval> >::iterator lossIt, lossEnd;
	vector<pair<timeval, sent_type> >::iterator sentIt, sentEnd;
	map<seq64_t, ByteRange*>::iterator range;

	// Extract total values from ranges
	typedef vector<double> lossvec;
	unique_ptr<lossvec> total_count(new lossvec());
	unique_ptr<lossvec> total_bytes(new lossvec());
	unique_ptr<lossvec> total_new_bytes(new lossvec());
	lossvec& tc = *total_count.get();
	lossvec& tb = *total_bytes.get();
	lossvec& tn = *total_new_bytes.get();

	for (range = analyse_range_start; range != analyse_range_end; ++range) {
		sentIt = range->second->sent_tstamp_pcap.begin();
		sentEnd = range->second->sent_tstamp_pcap.end();

		if (sentIt != sentEnd && range->second->packet_sent_count > 0) {
			uint64_t bucket_idx = intervalIdx((*sentIt).first, first_tstamp);

			while (bucket_idx >= tc.size()) {
				tc.push_back(0);
				tb.push_back(0);
				tn.push_back(0);
			}

			tn[bucket_idx] += range->second->original_payload_size;
		}

		// Place sent counts and byte counts in the right bucket
		for (; sentIt != sentEnd; ++sentIt)
		{
			uint64_t bucket_idx = intervalIdx((*sentIt).first, first_tstamp);

			while (bucket_idx >= tc.size()) {
				tc.push_back(0);
				tb.push_back(0);
				tn.push_back(0);
			}

			tc[bucket_idx] += 1;
			tb[bucket_idx] += range->second->byte_count;
		}
	}

	// Calculate loss values
	for (range = analyse_range_start; range != analyse_range_end; ++range) {
		lossIt = range->second->lost_tstamps_tcp.begin();
		lossEnd = range->second->lost_tstamps_tcp.end();

		if (lossIt != lossEnd &&
			range->second->packet_sent_count > 0 &&
			lossIt->second == range->second->sent_tstamp_pcap[0].first) {
			uint64_t bucket_idx = intervalIdx(range->second->sent_tstamp_pcap[0].first, first_tstamp);

			while (bucket_idx >= loss.size()) {
				loss.push_back(LossInterval(0, 0, 0));
			}

			loss[bucket_idx] += LossInterval(0, 0, range->second->original_payload_size);
		}

		// Place loss values in the right bucket
		for (; lossIt != lossEnd; ++lossIt) {
			uint64_t bucket_idx = intervalIdx(lossIt->second, first_tstamp);

			while (bucket_idx >= loss.size()) {
				loss.push_back(LossInterval(0, 0, 0));
			}

			loss[bucket_idx] += LossInterval(1, range->second->byte_count, 0);
		}
	}

	const uint64_t num_buckets = loss.size();
	while (num_buckets >= all_loss.size()) {
		all_loss.push_back(LossInterval(0, 0, 0));
	}

	// Set total values
	for (uint64_t idx = 0; idx < num_buckets; ++idx) {
		all_loss[idx] += loss[idx];
		all_loss[idx].addTotal(tc[idx], tb[idx], tn[idx]);
		loss[idx].addTotal(tc[idx], tb[idx], tn[idx]);
	}
}


/*
  Generates the retransmission data for the R files.
  The latency for each range is stored based on the
  number of tetransmissions for the range.
  The aggregation option controls of per stream or only
  aggregated result files should be made.
*/
void RangeManager::genAckLatencyData(const int64_t first_tstamp, vector<SPNS::shared_ptr<vector <LatencyItem> > > &diff_times,
									 const string& connKey) {
	map<seq64_t, ByteRange*>::iterator it, it_end;
	it = analyse_range_start;
	it_end = analyse_range_end;

	ulong num_retr_tmp;
	int ack_time_ms;
	int64_t send_time_ms;

	for (; it != it_end; it++) {
		ack_time_ms = static_cast<int>(it->second->getSendAckTimeDiff(this));

		if (ack_time_ms > 0) {
			ack_time_ms /= 1000;
			num_retr_tmp = (ulong) it->second->getNumRetrans();

			send_time_ms = TV_TO_MS(it->second->sent_tstamp_pcap[0].first);
			send_time_ms -= first_tstamp;

			if (num_retr_tmp >= diff_times.size()) {
				update_vectors_size(diff_times, num_retr_tmp +1);
			}

			diff_times[0]->push_back(LatencyItem(static_cast<int>(send_time_ms), ack_time_ms, connKey));
			if (num_retr_tmp) {
				diff_times[num_retr_tmp]->push_back(LatencyItem(static_cast<int>(send_time_ms), ack_time_ms, connKey));
			}
		}
	}
}
