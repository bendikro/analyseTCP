#include "RangeManager.h"
#include "Connection.h"
#include "ByteRange.h"
#include "analyseTCP.h"
#include "color_print.h"
#include "util.h"

map<const long, int> GlobStats::cdf;
map<const int, int> GlobStats::dcCdf;
float GlobStats::avgDrift = 0;

RangeManager::~RangeManager() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	for (; it != it_end; it++) {
		delete it->second;
	}

	vector<DataSeg*>::iterator rit, rit_end;
	rit = recvd.begin();
	rit_end = recvd.end();
	for (; rit != rit_end; rit++) {
		delete *rit;
	}
}

bool RangeManager::hasReceiveData() {
	return !recvd.empty();
}


/* Register all bytes with a common send time as a range */
void RangeManager::insertSentRange(struct sendData *sd) {
	static ulong startSeq;
	static ulong endSeq;
	static int ranges_size;

	startSeq = sd->data.seq;
	endSeq = sd->data.endSeq;

	if (GlobOpts::debugLevel == 6) {
		printf("\ninsertSentRange - retrans: %d, is_rdb %d\n", sd->data.retrans, sd->data.is_rdb);
	}

	insert_byte_range(startSeq, endSeq, true, &(sd->data), 0);

	ranges_size = ranges.size();
	if (ranges_size <= 1 && sd->data.payloadSize == 0) { /* First or second packet in stream */
		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
			cerr << "-------Creating first range---------" << endl;
		lastSeq = endSeq;
	}
	else if (startSeq == lastSeq) { /* Next packet in correct sequence */

		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
			cerr << "-------New range equivalent with packet---------" << endl;
			printf("%s - inserted Range with startseq: %lu\n", conn->getConnKey().c_str(), relative_seq(startSeq));
		}
		lastSeq = startSeq + sd->data.payloadSize;

		if (GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5) {
			cerr << "Inserting sent data: startSeq=" << relative_seq(startSeq) << ", endSeq=" << relative_seq(endSeq) << endl;
			if (startSeq == 0  || endSeq == 0){
				cerr << "Erroneous seq." << endl;
			}
		}
	}

	/* Check for instances where sent packets are lost from the packet trace */

	/* TODO: Add this as a warning if incomplete dump option is not given */
	else if (startSeq > lastSeq) {
		// This is most probably the ack on the FIN ack from receiver, so ignore
		if (sd->data.payloadSize != 0) {
			cerr << "RangeManager::insertRange: Missing byte in send range in conn '" << conn->getConnKey() << "'. " << endl;
			printf("Absolute: lastSeq: %lu, startSeq: %lu. Relative: lastSeq: %lu, startSeq: %lu\n",
				   lastSeq, startSeq, relative_seq(lastSeq), relative_seq(startSeq));
			cerr << "This is an indication that tcpdump has dropped packets while collecting the trace." << endl;
			exit_with_file_and_linenum(1, __FILE__, __LINE__);
		}
	}
	else if (startSeq > lastSeq) {

		// This is an ack
		if (sd->data.payloadSize == 0) {
			lastSeq = startSeq + sd->data.payloadSize;
		}
		else {
			lastSeq = startSeq + sd->data.payloadSize;
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->data.payloadSize);
			}
		}
	}
	else if (startSeq < lastSeq) { /* We have some kind of overlap */

		if (endSeq <= lastSeq) {/* All bytes are already registered: Retransmission */

			if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
				cerr << "-------All bytes have already been registered - discarding---------" << endl;
			redundantBytes += (endSeq +1 - startSeq);
			if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
				cerr << "Adding " << (endSeq +1 - startSeq)
					 << " redundant bytes to connection." << endl;
			}
		} else { /* Old and new bytes: Bundle */
			if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
				cerr << "-------Overlap: registering some bytes---------" << endl;

			if ((endSeq - startSeq +1) != sd->data.payloadSize) {
				printf("Data len incorrect!\n");
				exit_with_file_and_linenum(1, __FILE__, __LINE__);
			}

			lastSeq = startSeq + sd->data.payloadSize;
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->data.payloadSize);
			}
		}
	}

	if ((startSeq + sd->data.payloadSize) > largestEndSeq) {
		largestEndSeq = startSeq + sd->data.payloadSize;
	}
}

/* Register all bytes with a common send time as a range */
void RangeManager::insertRecvRange(struct sendData *sd) {
	static struct DataSeg *tmpSeq;
	tmpSeq = new struct DataSeg();

	tmpSeq->seq = sd->data.seq;
	tmpSeq->endSeq = sd->data.endSeq;
	tmpSeq->tstamp_pcap = (sd->data.tstamp_pcap);
	tmpSeq->data = sd->data.data;
	tmpSeq->payloadSize = sd->data.payloadSize;
	tmpSeq->is_rdb = sd->data.is_rdb;
	tmpSeq->retrans = sd->data.retrans;
	tmpSeq->tstamp_tcp = sd->data.tstamp_tcp;
	tmpSeq->window = sd->data.window;
	tmpSeq->flags = sd->data.flags;

	if (tmpSeq->payloadSize > 0)
		tmpSeq->endSeq -= 1;

	if (GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5) {
		cerr << "Inserting receive data: startSeq=" << relative_seq(tmpSeq->seq) << ", endSeq=" << relative_seq(tmpSeq->endSeq) << endl;
		if (tmpSeq->seq == 0 || tmpSeq->endSeq == 0) {
			cerr << "Erroneous seq." << endl;
		}
	}
	/* Insert all packets into data structure */
	recvd.push_back(tmpSeq);
	return;
}

/*
  This inserts the the data into the ranges map.
  It's called both with sent end received data ranges.
 */
void RangeManager::insert_byte_range(ulong start_seq, ulong end_seq, bool sent, struct DataSeg *data_seg, int level) {
	ByteRange *last_br = NULL;
	map<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt_end = ranges.end();
	brIt = brIt_end;

#ifdef DEBUG
	int debug_print = GlobOpts::debugLevel == 6;

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
		indent_print("insert_byte_range (%lu): (%lu - %lu) (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq == start_seq ? 0 : end_seq - start_seq +1,
			     relative_seq(start_seq), relative_seq(end_seq), start_seq, end_seq, sent, data_seg->retrans, data_seg->is_rdb);
	}
#endif
	// An ack
	if (start_seq == end_seq) {
		//If not SYN, it's ack, so return
		if (!(data_seg->flags & TH_SYN) && !(data_seg->flags & TH_FIN)) {
#ifdef DEBUG
			if (debug_print) {
				printf("Return ack ! syn\n");
			}
#endif
			return;
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
			indent_print2("Received non-existent byte range!\n");
#endif
			warn_with_file_and_linenum(__FILE__, __LINE__);
		}

#ifdef DEBUG
		if (debug_print) {
			indent_print("Adding: %lu - %lu (start_seq: %lu)\n", relative_seq(start_seq), relative_seq(end_seq), start_seq);
		}
#endif
		// Ack / syn-ack / fin
		if (end_seq == start_seq) {
#ifdef DEBUG
			if (!sent)
				assert(0 && "RECEIVED!");
#endif
			last_br = new ByteRange(start_seq, end_seq);
			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
			last_br->retrans_count += data_seg->retrans;
			last_br->rdb_count += data_seg->is_rdb;
			ranges.insert(pair<ulong, ByteRange*>(start_seq, last_br));
			return;
		}

		map<ulong, ByteRange*>::iterator lowIt, highIt;
		lowIt = ranges.lower_bound(start_seq +1);
		highIt = ranges.upper_bound(end_seq);

		ulong new_end_seq = end_seq;

		// Try to find existing range with start-seq > startSeq and endSeq <= lowIt->second->endSeq
		for (; lowIt != highIt && lowIt != highIt; lowIt++) {
#ifdef DEBUG
			if (debug_print) {
				indent_print("FOUND: sent: %d  %lu - %lu\n", sent, lowIt->second->startSeq, lowIt->second->endSeq);
			}
			assert(0 && "Should never happen!!\n");
#endif
			lowIt->second->sent_count++;

			if (new_end_seq == end_seq)
				new_end_seq = lowIt->second->startSeq -1;
		}

		if (start_seq < lastSeq) {
#ifdef DEBUG
			indent_print("FOUND: start_seq < lastSeq: %lu < %lu\n", start_seq, lastSeq);
#endif
			ulong lower = std::min(0UL, start_seq - 10000);
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
					assert(lowIt->second->startSeq != start_seq && "New Data is at beginning of existing range!!\n");
#endif
					// Splitting existing range
					int end_matches = (end_seq == lowIt->second->endSeq);
					ByteRange *cur_br = lowIt->second;

#ifdef DEBUG
					if (debug_print) {
						indent_print("SENT: %d, rdb: %d, retrans: %d\n", sent, data_seg->is_rdb, data_seg->retrans);
						indent_print("\nFound existing range with matching data\n            for: %lu - %lu!\n", relative_seq(start_seq), relative_seq(end_seq));
						indent_print("Existing range : %lu - %lu\n", relative_seq(lowIt->second->startSeq), relative_seq(lowIt->second->endSeq));
						indent_print("Old Range      : %lu - %lu\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq));
					}
#endif
					// Split the current range in two. The new range will be at the beginning of the old (existing range)
					// The new data matches the existing data
					ByteRange *new_br = cur_br->split_start(cur_br->startSeq, start_seq -1);

					if (sent) {
						cur_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
						cur_br->retrans_count += data_seg->retrans;
						cur_br->rdb_count += data_seg->is_rdb;
#ifdef DEBUG
						assert(!(!this_is_rdb_data && data_seg->is_rdb) && "Should not be retrans!\n");

						if (this_is_rdb_data) {
							assert(data_seg->retrans == 0 && "Should not be retrans!\n");
						}
						else {
							// Must this be retrans
							assert(data_seg->retrans != 0 && "Should be retransmission!\n");
						}
#endif
					}
					else {
						cur_br->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
						//assert(0 && "TEST\n");
						assert(cur_br->received_tstamp_tcp && "TEST\n");
						//new_br->split_after_sent = true;
					}

#ifdef DEBUG
					if (debug_print) {
						indent_print("New Range      : %lu - %lu\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq));
						indent_print("Old Range      : %lu - %lu\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq));
					}
#endif
					// Remove current Range
					ranges.erase(lowIt++);
					// Add existing and new range with correct key
					ranges.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
					ranges.insert(pair<ulong, ByteRange*>(cur_br->startSeq, cur_br));

					if (!end_matches) {
						//indent_print("End seqs do not match! %lu != %lu\n", relative_seq(end_seq), relative_seq(cur_br->endSeq));
						if (cur_br->endSeq > end_seq) {
							ByteRange *new_br = cur_br->split_end(end_seq + 1, cur_br->endSeq);
							ranges.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
							return;
						}
#ifdef DEBUG
						else {
							assert(0 && "Shouldn't come here!?\n");
						}
#endif
					}
					else {
						return;
					}
				}
				else
					lowIt++;
			}
		}

		if (sent) {
#ifdef DEBUG
			if (debug_print) {
				indent_print("data_seg->is_rdb: %d\n", data_seg->is_rdb  );
				indent_print("data_seg->rdb_end_seq > start_seq: %lu > %lu: %d\n", relative_seq(data_seg->rdb_end_seq), relative_seq(start_seq), data_seg->rdb_end_seq > start_seq);
			}
#endif
			last_br = new ByteRange(start_seq, new_end_seq);
			if (data_seg->is_rdb) {
				last_br->original_payload_size = data_seg->payloadSize;
			}
			last_br->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);

#ifdef DEBUG
			assert(data_seg->retrans == 0 && "Shouldn't be retrans!\n");
			assert(this_is_rdb_data == 0 && "Shouldn't be RDB?!\n");

			if ((new_end_seq - start_seq) > 100) {
				if (debug_print) {
					indent_print("Inserting new big range: %lu\n", (new_end_seq - start_seq +1));
				}
			}
#endif
			ranges.insert(pair<ulong, ByteRange*>(start_seq, last_br));
		}
#ifdef DEBUG
		else {
			assert(sent && "RECEIVED??\n");
		}
#endif
	}
	// Exists in map
	else {
#ifdef DEBUG
		if (debug_print) {
			indent_print("FOUND START: sent:%d, %lu - %lu (%lu)\n", sent, relative_seq(start_seq), relative_seq(end_seq), end_seq - start_seq + 1);
			indent_print("Current startseq: %lu, endseq: %lu, new endseq: %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), relative_seq(end_seq));
		}
#endif
		// No payload, so it's a syn or syn-ack or fin
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
					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
				}
				else {
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
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
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
					//brIt->second->received_count++;
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
					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
					brIt->second->retrans_count += data_seg->retrans;
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
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
					assert(brIt->second->received_tstamp_tcp && "TEST\n");
				}

				// Recursive call to insert the remaining data
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
					brIt->second->retrans_count += data_seg->retrans;
					brIt->second->rdb_count += data_seg->is_rdb;
					brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
#ifdef DEBUG
					if (this_is_rdb_data) {
						assert(data_seg->retrans != 0 && "Should not be retrans!\n");
					}
#endif
				}
				else {
					new_br->split_after_sent = true;
					brIt->second->split_after_sent = true;
					brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
				}
				ranges.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
			}
		}
		else {
			// The end_seq of the new range correspond to the end-seq of the entry in the map, so it's a duplicate
			if (sent) {
				brIt->second->increase_sent(data_seg->tstamp_tcp, data_seg->tstamp_pcap, this_is_rdb_data);
				brIt->second->retrans_count += data_seg->retrans;
				brIt->second->rdb_count += data_seg->is_rdb;
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
				brIt->second->increase_received(data_seg->tstamp_tcp, data_seg->tstamp_pcap);
#ifdef DEBUG
				if (debug_print) {
					printf("Setting received timestamp: %u\n", brIt->second->received_tstamp_tcp);
					printf("tstamps: %lu, rdb-stamps: %lu", brIt->second->tstamps_tcp.size(), brIt->second->rdb_tstamps_tcp.size());
				}
				assert(brIt->second->received_tstamp_tcp && "TEST\n");
#endif
			}
		}
	}
}


/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAck(struct DataSeg *seg /*ulong ack, timeval* tv, ulong th_win*/) {
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
		printf("ProcessACK: %8lu  (%8lu), win=%6lu TSVal: %u, last acked start seq: %lu\n", relative_seq(ack), ack, seg->window*128, seg->tstamp_tcp,
		       relative_seq(it->second->getStartSeq()));
		printf("ProcessACK: %lu (%lu), last acked start seq: %lu\n", relative_seq(ack), ack, relative_seq(it->second->getStartSeq()));

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
			tmpRange->insertAckTime(&seg->tstamp_pcap);
			highestAckedByteRangeIt = it;
			//highestAckedByteRangeIt++;
			ret = true;
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

			// Second part of range: insert after tmpRange (tmpRange)
			highestAckedByteRangeIt = ranges.insert(std::pair<ulong, ByteRange*>(new_br->getStartSeq(), new_br)).first;
			//ranges.insert(std::pair<ulong, ByteRange*>(new_br->getStartSeq(), new_br));
			return true;
		}

		/* If we get here, something's gone wrong */
		fprintf(stderr, "RangeManager::processAck: Error when processing ack: %lu (%lu)\n", relative_seq(ack), ack);
		fprintf(stderr, "Range(%lu, %lu) (%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()), tmpRange->getStartSeq(), tmpRange->getEndSeq());
		fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
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

Percentiles *percentiles(const vector<double> *v) {
    vector<double>::const_iterator it_second_half = v->begin() + v->size() / 2;
    vector<double>::const_iterator it_first_half = it_second_half;
    vector<double>::const_iterator it_ninetynine_p = v->begin() + ((int) v->size() * 0.99);
    vector<double>::const_iterator it_first_p = v->begin() + ((int) v->size() * 0.99);
    if ((v->size() % 2) == 0)
	    --it_first_half;

    double q1 = median(v->begin(), it_first_half);
    double q2 = median(v->begin(), v->end());
    double q3 = median(it_second_half, v->end());
    double p1 = median(v->begin(), it_first_p);
    double p99 = median(it_ninetynine_p, v->end());
    Percentiles *ret = new Percentiles(q1, q2, q3, p1, p99);
    return ret;
}


void RangeManager::genStats(struct byteStats *bs) {
	int latency;
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	vector<double> latencies;
	vector<double> payload_lengths;
	int tmp_byte_count = 0;
	bs->minLat = bs->minLength = (numeric_limits<int>::max)();

	map<const int, int> dupacks;
	int dupack_count;

	for (; it != it_end; it++) {
		// Skip if invalid (negative) latency
		tmp_byte_count = it->second->getOrinalPayloadSize();
		payload_lengths.push_back(tmp_byte_count);
		bs->cumLength += tmp_byte_count;
		for (int i = 0; i < it->second->getNumRetrans(); i++) {
			payload_lengths.push_back(tmp_byte_count);
			bs->cumLength += tmp_byte_count;
		}

		dupack_count = it->second->dupack_count;
		if (dupack_count > 0) {
			if (dupacks.count(dupack_count) > 0) {
				map<const int, int>::iterator element = dupacks.find(dupack_count);
				element->second++;
			} else {
				dupacks.insert(pair<int, int>(dupack_count, 1));
			}
		}

		if (tmp_byte_count) {
			if (tmp_byte_count > bs->maxLength)
				bs->maxLength = tmp_byte_count;
			if (tmp_byte_count < bs->minLength) {
				bs->minLength = tmp_byte_count;
			}
		}

		if ((latency = it->second->getSendAckTimeDiff(this))) {
			 latencies.push_back(latency);
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
		if (retrans > bs->maxRetrans)
			bs->maxRetrans = retrans;

		retrans = std::min(MAX_STAT_RETRANS, retrans);

		if (retrans > 0) {
			for (int i = 0; i < retrans; i++) {
				bs->retrans[i]++;
			}
		}
	}

	bs->dupacks = dupacks;

	double temp;
	double stdev;
	if (latencies.size()) {
		double sumLat = bs->cumLat;
		double mean =  sumLat / latencies.size();
		temp = 0;

		for (unsigned int i = 0; i < latencies.size(); i++) {
			temp += (latencies[i] - mean) * (latencies[i] - mean);
		}

		std::sort(latencies.begin(), latencies.end());

		stdev = sqrt(temp / (latencies.size()));
		bs->stdevLat = stdev;
		bs->percentiles_latencies = percentiles(&latencies);
	}
	else
		bs->minLat = 0;

	if (payload_lengths.size()) {
		// Payload size stats
		double sumLen = conn->totBytesSent;
		double meanLen =  sumLen / payload_lengths.size();
		bs->avgLength = meanLen;

		temp = 0;
		for (unsigned int i = 0; i < payload_lengths.size(); i++) {
			temp += (payload_lengths[i] - meanLen) * (payload_lengths[i] - meanLen);
		}

		std::sort(payload_lengths.begin(), payload_lengths.end());
		stdev = sqrt(temp / (payload_lengths.size()));
		bs->stdevLength = stdev;
		bs->percentiles_lengths = percentiles(&payload_lengths);
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
		printf("firstSeq: %lu, StartSeq: %lu\n", firstSeq, it->second->getStartSeq());
		printf("RangeManager::validateContent: firstSeq != StartSeq (%lu != %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(firstSeq));
		printf("First range (%lu, %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getEndSeq()));
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	if (!(ranges.rbegin()->second->getEndSeq() <= lastSeq && ranges.rbegin()->second->getEndSeq() >= (lastSeq - 1))) {
		printf("RangeManager::validateContent: lastSeq unaligned! lastSeq: %lu, EndSeq: %lu\n", relative_seq(lastSeq), relative_seq(ranges.rbegin()->second->getEndSeq()));
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	if (conn->totBytesSent != (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent)) {
		printf("conn->totBytesSent(%u) does not equal (totNewDataSent + totRDBBytesSent + totRetransBytesSent) (%u)\n",
		       conn->totBytesSent, (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent));
		warn_with_file_and_linenum(__FILE__, __LINE__);
	}

	for (it = ranges.begin(); it != it_end; it++) {

		// First element
		if (it == first) {
			tmpEndSeq = it->second->getEndSeq();
			continue;
		}

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
				exit_with_file_and_linenum(1, __FILE__, __LINE__);
			}
		}

		if (it->second->getSendTime())
			numSendTimes++;
		if (it->second->getAckTime())
			numAckTimes++;

		prev = it;
	}

	if (nrRanges == 0) {
		nrRanges = ranges.size();
	} else {
		if ((int)ranges.size() != nrRanges) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "Ranges has been resized. Old size: " << nrRanges
					 << " - New size: " << ranges.size() << endl;
		}
		nrRanges = ranges.size();

	}
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "First seq: " << firstSeq << " Last seq: " <<  lastSeq << endl;
		cerr << "Number of ranges: " << ranges.size() << endl;
		cerr << "Number of bytes: " << lastSeq - firstSeq << endl;
		cerr << "numSendTimes: " << numSendTimes << endl;
		cerr << "numAckTimes: " << numAckTimes << endl;
		cerr << "Is first range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Is last range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Last range: startSeq: " << ranges.begin()->second->getStartSeq()
			 << " - endSeq: " << ranges.begin()->second->getEndSeq() << endl;
	}
}


void RangeManager::write_loss_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *loss_retrans_out, FILE *loss_loss_out) {
	map<ulong, ByteRange*>::iterator brIt, brIt_end;
	int lost_count = 0;
	int retrans_count = 0;
	timeval next, t_slice, next_tmp;

	brIt = ranges.begin();
	brIt_end = ranges.end();
	t_slice.tv_sec = slice_interval;
	t_slice.tv_usec = 0;
	timeradd(&(brIt->second->sent_tstamp_pcap[0]), &t_slice, &next);

	fprintf(loss_retrans_out, "%45s", conn->getConnKey().c_str());
	if (loss_loss_out)
		fprintf(loss_loss_out, "%45s", conn->getConnKey().c_str());

	for (; brIt != brIt_end; brIt++) {

		// Print slice value and find next slice time
		while (!timercmp(&(brIt->second->sent_tstamp_pcap[0]), &next, <)) {
			fprintf(loss_retrans_out, ",%10d", lost_count);
			if (loss_loss_out)
				fprintf(loss_loss_out, ",%10d", lost_count);
			lost_count = 0;
			retrans_count = 0;
			memcpy(&next_tmp, &next, sizeof(struct timeval));
			timeradd(&next_tmp, &t_slice, &next);
			timeslice_count--;
		}
		retrans_count += brIt->second->retrans_count;
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

void RangeManager::printPacketDetails() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	int seq_char_len = SSTR(relative_seq(ranges.rbegin()->second->endSeq)).length();

	cout << endl << "Packet details for conn: " << conn->getConnKey() << endl;

	for (; it != it_end; it++) {
		printf("Byte range (%4lu, %4d): %-*lu - %-*lu: sent: %d, received: %d, retrans_count: %d, rdb_count: %d, RCV: %s, rdb-miss: %-3d rdb-hit: %-3d",
		       it->second->endSeq == it->second->startSeq ? 0 : it->second->endSeq - it->second->startSeq +1,
		       it->second->original_payload_size, seq_char_len,
		       relative_seq(it->second->startSeq), seq_char_len, relative_seq(it->second->endSeq), it->second->sent_count, it->second->received_count,
		       it->second->retrans_count, it->second->rdb_count, received_type_str[it->second->recv_type], it->second->rdb_byte_miss, it->second->rdb_byte_hits);
		printf(" ACKtime: %d", it->second->getSendAckTimeDiff(this));

		if (GlobOpts::withRecv) {
			if (it->second->sent_count != it->second->received_count) {
				printf("   LOST %d", it->second->sent_count - it->second->received_count);
			}
		}
		printf("\n");
	}
}

void RangeManager::calculateRDBStats() {
	ByteRange *prev = NULL;
	ulong index = 0;
	int lost_tmp = 0;
	map<ulong, ByteRange*>::iterator brIt, brIt_end;
	rdb_stats_available = true;

	int match_fails = 0;
	int match_fails_at_end = 0;
	int lost_packets = 0;
	bool prev_pack_lost = false;

	//bool has_recv_data = hasReceiveData();

	brIt = ranges.begin();
	brIt_end = ranges.end();
	for (; brIt != brIt_end; brIt++) {
		if (prev) {
			if (prev->endSeq +1 != brIt->second->startSeq && prev->startSeq != prev->endSeq) {
				//printf("Range not continuous!\n Gap in %lu:%lu - %lu:%lu\n", prev->startSeq, prev->endSeq, brIt->second->startSeq, brIt->second->endSeq);
			}
		}
		prev = brIt->second;
		index++;

		bool ret = brIt->second->match_received_type();
		if (ret == false) {
			colored_printf(RED, "Failed to match %lu - %lu (index: %lu)\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), index);
			brIt->second->print_tstamps_tcp();
			if (index > (ranges.size() - 20)) {
				match_fails_at_end++;
			}
			else
				match_fails++;
		}

		int rdb_count = brIt->second->rdb_count;
		if (rdb_count && brIt->second->recv_type == RDB) {
			rdb_count -= 1; // Remove the successful rdb transfer
			brIt->second->rdb_byte_hits = brIt->second->byte_count;
			rdb_byte_hits += brIt->second->byte_count;
		}

		if (brIt->second->recv_type == RDB) {
			rdb_packet_hits++;
		}

		brIt->second->rdb_byte_miss = rdb_count * brIt->second->byte_count;
		rdb_byte_miss += brIt->second->rdb_byte_miss;
		sent_ranges_count += brIt->second->sent_count;

		if (brIt->second->sent_count != brIt->second->received_count) {
			if (GlobOpts::print_packets) {
				//printf("   LOST %d, index: %lu", brIt->second->sent_count - brIt->second->received_count, index);
			}
			lost_ranges_count += (brIt->second->sent_count - brIt->second->received_count);
			lost_bytes += (brIt->second->sent_count - brIt->second->received_count) * brIt->second->byte_count;
			ulong lost = (brIt->second->sent_count - brIt->second->received_count);

			// Must check if this lost packet is the same packet as for the previous range
			if (prev_pack_lost) {
				for (ulong i = 0; i < brIt->second->lost_tstamps_tcp.size(); i++) {
					for (ulong u = 0; u < prev->lost_tstamps_tcp.size(); u++) {
						if (brIt->second->lost_tstamps_tcp[i] == prev->lost_tstamps_tcp[u]) {
							lost -= 1;
							//printf(" same as prev!");
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

		if (GlobOpts::print_packets) {
			if (!brIt->second->retrans_count && !brIt->second->rdb_count && (brIt->second->rdb_byte_miss || brIt->second->rdb_byte_hits)) {
				printf(" FAIL (RDB hit/miss calculalation has failed)!");
			}
		}

		if (brIt->second->sent_count > 1)
			lost_tmp += brIt->second->sent_count - 1;
		else {
			// Necessary for correct index when multiple packets in a row are lost
			index += lost_tmp;
			lost_tmp = 0;
		}
		if (GlobOpts::print_packets) {
			//printf("\n");
		}
	}
	if (match_fails)
		printf("Failed to find timestamp for %d out of %ld packets.\n", match_fails, ranges.size());
	if (match_fails_at_end)
		printf("Failed to find timestamp for %d out of %ld packets. These packets were at the end of the stream"\
			   ", so presumable they just not caught by tcpdump.\n", match_fails_at_end, ranges.size());

	//printf("Lost packets: %d\n", lost_packets);
	//printf("sent_ranges_count: %d\n", sent_ranges_count);
	//printf("lost_ranges_count: %d\n", lost_ranges_count);
	//printf("Ranges loss: %f\n", (double) lost_ranges_count / sent_ranges_count);
}


void RangeManager::calculateRetransAndRDBStats() {
	vector<DataSeg*>::iterator rit, rit_end;
	/* Create map with references to the ranges */
	rit = recvd.begin();
	rit_end = recvd.end();

	for (; rit != rit_end ; rit++) {
		struct DataSeg *tmpRd = *rit;
		insert_byte_range(tmpRd->seq, tmpRd->endSeq, false, tmpRd, 0);
	}
	calculateRDBStats();
}

/* Reads all packets from receiver dump into a vector */
void RangeManager::registerRecvDiffs() {
	vector<DataSeg*>::iterator rit, rit_end;

	/* Create map with references to the ranges */
	rit = recvd.begin();
	rit_end = recvd.end();
	multimap<ulong, struct DataSeg*> rsMap;

	for (; rit != rit_end ; rit++) {
		struct DataSeg *tmpRd = *rit;
		rsMap.insert(pair<ulong, struct DataSeg*>(tmpRd->seq, tmpRd));
	}

	std::pair <std::multimap<ulong, struct DataSeg*>::iterator, std::multimap<ulong, struct DataSeg*>::iterator> ret;

	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	int ranges_not_received = 0;
	int packet_index = -1;
	for (; it != it_end; it++) {
		int matched = -1;
		ulong sndStartSeq = it->second->getStartSeq();
		ulong sndEndSeq = it->second->getEndSeq();

		packet_index++;
/*
		printf("Range (%4lu): %lu - %lu: retrans_count: %d, rdb_count: %d",
			   it->second->getEndSeq() - it->second->getStartSeq() +1,
			   relative_seq(it->second->getStartSeq()), relative_seq(it->second->getEndSeq()),
			   it->second->getNumRetrans(), it->second->getNumBundled());
		printf(" ACKtime: %d\n", it->second->getSendAckTimeDiff(this));
*/
		if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
			cerr << "Processing range:                    " << relative_seq(sndStartSeq) << " - " << relative_seq(sndEndSeq) << "- Sent:"
				 << it->second->getSendTime()->tv_sec << "." << it->second->getSendTime()->tv_usec << endl;
		}

		// If sent packet is an ack, it's not registered on receiver side as data, so ignore
		if (it->second->getNumBytes() == 0) {
			continue;
		}

		/* Traverse recv data structs to find
		   lowest time for all corresponding bytes */
		multimap<ulong, struct DataSeg*>::iterator lowIt, highIt;
		/* Add and subtract one MTU(and some) from the start seq
		   to get range of valid packets to process */
		ulong msRange = 1600;

		ulong absLow = sndStartSeq - msRange;
		ulong absHigh = sndStartSeq + msRange;

		if (sndStartSeq < msRange) {
			absLow = 0;
		}

		lowIt = rsMap.lower_bound(absLow);
		highIt = rsMap.upper_bound(absHigh);

		struct timeval match;
		memset(&match, 9, sizeof(match));

		if (GlobOpts::debugLevel == 7) {
			printf("\n\nSent        seq: (%10lu - %10lu) Len: %u\n", relative_seq(sndStartSeq), relative_seq(sndEndSeq), it->second->getNumBytes());
		}

		if (GlobOpts::debugLevel == 7) {
			printf("Searching       : %lu - count: %ld\n", relative_seq(sndStartSeq), rsMap.count(sndStartSeq));
		}

		for (; lowIt != highIt; lowIt++) {
			struct DataSeg *tmpRd = lowIt->second;
			int match_count = 0;

			if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
				cerr << "\nProcessing received packet with seq: " <<
					relative_seq(tmpRd->seq) << " - " << relative_seq(tmpRd->endSeq) << " | Recvd:"
					 << tmpRd->tstamp_pcap.tv_sec << "." << tmpRd->tstamp_pcap.tv_usec << endl;
				if (GlobOpts::debugLevel == 5) {
					cerr << "absLow: " << relative_seq(absLow) << " - absHigh: " << relative_seq(absHigh) << endl;
				}
			}

			if (GlobOpts::debugLevel == 7) {
				printf("   Checking seq: (%5lu - %5lu)\n", relative_seq(tmpRd->seq), relative_seq(tmpRd->endSeq));
			}
			/* If the received packet matches the range */
			if (tmpRd->seq <= sndStartSeq && tmpRd->endSeq >= sndEndSeq) {
				/* Set match time to the lowest observed value that
				   matches the range */
				match_count++;

				if (GlobOpts::debugLevel == 7) {
					printf("   Receieved seq: %10lu         -      %10lu\n", relative_seq(tmpRd->seq), relative_seq(tmpRd->endSeq));
				}

				if (timercmp(&(tmpRd->tstamp_pcap), &match, <))
					match = tmpRd->tstamp_pcap;
				matched = packet_index;
				//it->second->received++;

				if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
					cerr << "Found overlapping DataSeg:     seq: " <<
						relative_seq(tmpRd->seq) << " - " << relative_seq(tmpRd->endSeq) << " - Recvd:"
						 << tmpRd->tstamp_pcap.tv_sec << "." << tmpRd->tstamp_pcap.tv_usec << endl;
				}

				if (tmpRd->seq == sndStartSeq && tmpRd->endSeq == sndEndSeq) {

					if (GlobOpts::debugLevel == 7) {
						printf("               Found exact match");
					}
					break;
				}
				else if (tmpRd->seq >= sndStartSeq && tmpRd->endSeq <= sndEndSeq) {
					break;
				}
			}
		}

		/* Check if match has been found */
		/* Tag as dummy range? */
		if (matched == -1) {
			// We found the next after the expected, this is the ack on the fin (if payload is 0)
			int count = rsMap.count(it->second->getStartSeq() +1);
			if (count) {
				struct DataSeg *tmpRd = rsMap.find(it->second->getStartSeq() +1)->second;
				if (tmpRd->payloadSize != 0) {
					count = 0;
				}
			}

			if (!count) {
				assert(0 && "Some ranges were not received!");
				ranges_not_received++;
				if (GlobOpts::debugLevel == 8) {
					fprintf(stderr, "Packet not found on receiver (%lu - %lu) Len: %u\n",
						relative_seq(it->second->getStartSeq()),
						relative_seq(it->second->getEndSeq()),  it->second->getNumBytes());
				}
				continue;
			}
		}

		//it->second->setRecvTime(&match);

		if (GlobOpts::transport) {
			it->second->setRecvTime(&match);
		} else {
			/* Use lowest time that has been found for this range,
			   if the timestamp is lower than the highest time we
			   have seen yet, use the highest time (to reflect application
			   layer delay) */
			if (timercmp(&match, &highestRecvd, >)) {
				highestRecvd = match;
			}
			it->second->setRecvTime(&highestRecvd);
		}

		/* Calculate diff and check for lowest value */
		it->second->setDiff();
		long diff = it->second->getRecvDiff();
		if (diff < lowestDiff)
			lowestDiff = diff;

		if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
			cerr << "SendTime: " << it->second->getSendTime()->tv_sec << "."
				 << it->second->getSendTime()->tv_usec << endl;
			cerr << "RecvTime: " << it->second->getRecvTime()->tv_sec << "."
				 << it->second->getRecvTime()->tv_usec << endl;
			cerr << "RecvDiff=" << diff << endl;
			cerr << "recvd.size()= " << recvd.size() << endl;
		}
	}

	if (ranges_not_received) {
		cout << conn->getSrcIp() << ":" << conn->srcPort << " -> " << conn->getDstIp() << ":" << conn->dstPort << " : ";
		fprintf(stdout, "Found %d ranges that have no corresponding received packet.\n", ranges_not_received);
	}
}

ulong RangeManager::relative_seq(ulong seq) {
	if (GlobOpts::relative_seq)
		return seq;
	ulong wrap_index;
	wrap_index = (conn->firstSeq + seq) / 4294967296L;
//	printf("relative_seq: seq: %lu, first + seq: %lu, wrap_index: %lu\n", seq, conn->firstSeq + seq, wrap_index);
	ulong res = seq + firstSeq;
	res -= ((ulong) wrap_index * 4294967296L);
	//printf("relative_seq  ret: %lu\n", res);
	return res;
}

ByteRange* RangeManager::getHighestAcked() {
	if (highestAckedByteRangeIt == ranges.end())
		return NULL;
	return highestAckedByteRangeIt->second;
}

/* Returns duration of connection (in seconds)*/
uint32_t RangeManager::getDuration() {
	uint32_t time;
	struct timeval startTv, endTv, tv;
	endTv = *(ranges.rbegin()->second->getSendTime());
	startTv = *(ranges.begin()->second->getSendTime());
	timersub(&endTv, &startTv, &tv);
	time = tv.tv_sec + (tv.tv_usec / 1000000);
	return time;
}

/* Calculate clock drift on CDF */
int RangeManager::calcDrift() {
	/* If connection > 500 ranges &&
	   connection.duration > 120 seconds,
	   calculate clock drift */

	if (ranges.size() > 500 && getDuration() > 120) {
		map<ulong, ByteRange*>::iterator startIt;
		map<ulong, ByteRange*>::reverse_iterator endIt;
		long minDiffStart = LONG_MAX;
		long minDiffEnd = LONG_MAX;
		struct timeval minTimeStart, minTimeEnd, tv;
		int time;
		float tmpDrift;
		memset(&minTimeStart, 0, sizeof(struct timeval));
		memset(&minTimeEnd, 0, sizeof(struct timeval));

		startIt = ranges.begin();
		for (int i = 0; i < 200; i++) {
			if(startIt->second->getRecvDiff() < minDiffStart){
				minDiffStart = startIt->second->getRecvDiff();
				minTimeStart = *(startIt->second->getSendTime());
			}
			startIt++;
		}

		endIt = ranges.rbegin();
		for (int i = 0; i < 200; i++) {
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
		time = tv.tv_sec + (tv.tv_usec / 1000000);

		tmpDrift = (float)(minDiffEnd - minDiffStart) / time;

		if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
			cerr << "startMin: " << minDiffStart << endl;
			cerr << "endMin: " << minDiffEnd << endl;
			cerr << "Time: " << time << endl;
			cerr << "Clock drift: " << tmpDrift << " ms/s" << endl;
		}
		drift = tmpDrift;
	} else {
		if (GlobOpts::debugLevel != 0) {
				cerr << "\nConnection has less than 500 ranges or a duration of less than 2 minutes." << endl;
				cerr << "Drift-compensated CDF will therefore not be calculated." << endl;
			}
		drift = -1;
		return -1;
	}
	return 0;
}

void RangeManager::makeCdf() {
	long diff;
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for (; it != it_end; it++) {
		diff = it->second->getRecvDiff();
		diff -= lowestDiff;

		if (cdf.count(diff) > 0) {
			/*  Add bytes to bucket */
			map<const long, int>::iterator element = cdf.find(diff);
			element->second = element->second + it->second->getNumBytes();
		} else {
			/* Initiate new bucket */
			cdf.insert(pair<long, int>(diff, it->second->getNumBytes()));
		}
		if (GlobOpts::aggregate) {
			if ( GlobStats::cdf.count(diff) > 0 ){
				/*  Add bytes to bucket */
				map<const long, int>::iterator element = GlobStats::cdf.find(diff);
				element->second = element->second + it->second->getNumBytes();
			} else {
				/* Initiate new bucket */
				GlobStats::cdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
			}
		}
	}
}

/* Returns the difference between the start
   of the dump and r in seconds */
inline int RangeManager::getTimeInterval(ByteRange *r) {
	struct timeval start, current, tv;
	int time;
	start = *(ranges.begin()->second->getSendTime());
	current = *(r->getSendTime());
	timersub(&current, &start, &tv);
	time = tv.tv_sec + (tv.tv_usec / 1000000);
	return time;
}


void RangeManager::registerDcDiffs() {
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff();
		/* Compensate for drift */
		diff -= (int)(drift * getTimeInterval(it->second));

		it->second->setDcDiff(diff);

		if (diff < lowestDcDiff)
			lowestDcDiff = diff;

		if(GlobOpts::debugLevel==4 || GlobOpts::debugLevel==5){
			cerr << "dcDiff: " << diff << endl;
		}
	}
}

void RangeManager::makeDcCdf() {

	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for (; it != it_end; it++) {
		long diff = it->second->getDcDiff() - lowestDcDiff;
		if (dcCdf.count(diff) > 0) {
			/*  Add bytes to bucket */
			map<const int, int>::iterator element = dcCdf.find(diff);
			//printf("setting getNumBytes: %d\n", it->second->getNumBytes());
			//element->second = element->second + it->second->getOrinalPayloadSize();
			element->second = element->second + it->second->getNumBytes();
		} else {
			/* Initiate new bucket */
			dcCdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
		}
		if (GlobOpts::aggregate) {
			if (GlobStats::dcCdf.count(diff) > 0) {
				/*  Add bytes to bucket */
				map<const int, int>::iterator element = GlobStats::dcCdf.find(diff);
				element->second = element->second + it->second->getNumBytes();
			} else {
				/* Initiate new bucket */
				GlobStats::dcCdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
			}
		}

		if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
			it->second->printValues();
		}
	}
	GlobStats::totNumBytes += getNumBytes();

	if (drift != -1) {
		if (GlobStats::avgDrift == 0)
			GlobStats::avgDrift = drift;
		else
			GlobStats::avgDrift = (GlobStats::avgDrift + drift) / 2;
	}
}

void RangeManager::writeCDF(ofstream *stream) {
	map<const long, int>::iterator nit, nit_end;
	double cdfSum = 0;
	char print_buf[300];
	nit = cdf.begin();
	nit_end = cdf.end();

	if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
		*stream << "lowestDiff: " << lowestDiff << endl;
	}

	*stream << "#Relative delay      Percentage" << endl;
	for (; nit != nit_end; nit++) {
		//printf("first: %ld, second: %d, numBytes: %d, second/NumBytes: %f\n", (*nit).first, (*nit).second, getNumBytes(), (double) (*nit).second / getNumBytes());
		//printf("second: %d, numBytes: %d\n", (*nit).second, getNumBytes());
		//printf("first: %ld, second: %d\n", (*nit).first, (*nit).second);
		cdfSum += (double) (*nit).second / getNumBytes();
		sprintf(print_buf, "time: %10ld    CDF: %.10f", (*nit).first, cdfSum);
		printf("%s\n", print_buf);
		*stream << print_buf << endl;
	}
}

void RangeManager::writeDcCdf(ofstream *stream) {
	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	char print_buf[300];
	nit = dcCdf.begin();
	nit_end = dcCdf.end();

	if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
		cerr << "lowestDcDiff: " << lowestDcDiff << endl;
	}

	/* Do not print cdf for short conns */
	if (drift == -1)
		return;

	*stream << "#------ Drift : " << drift << "ms/s ------" << endl;
	*stream << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / getNumBytes();
		sprintf(print_buf, "time: %10d    CDF: %.10f", (*nit).first, cdfSum);
		*stream << print_buf << endl;
	}
}

/*
  Generates the retransmission data for the R files.
  The latency for each range is stored based on the
  number of tetransmissions for the range.
*/
void RangeManager::genRFiles(string connKey) {
	stringstream filename_tmp;
	vector<ofstream*> streams;
	map<ulong, ByteRange*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	if (!(GlobOpts::aggOnly)) {
		for (unsigned long int i = 0; i < GlobStats::retrans_filenames.size(); i++) {
			filename_tmp.str("");
			filename_tmp << GlobStats::retrans_filenames[i] << connKey << ".dat";
			streams.push_back(new ofstream(filename_tmp.str().c_str(), ios::out));
		}
	}

	int num_retr_tmp;
	int diff_tmp;
	for (; it != it_end; it++) {
		diff_tmp = it->second->getSendAckTimeDiff(this);
		if (diff_tmp > 0) {
			num_retr_tmp = it->second->getNumRetrans();
			// all
			GlobStats::ack_latency_vectors[0]->push_back(diff_tmp);
			// Retrans vector for that number of retransmissions
			if (num_retr_tmp <= GlobOpts::max_retrans_stats)
				GlobStats::ack_latency_vectors[num_retr_tmp]->push_back(diff_tmp);

			// Write to file
			if (!(GlobOpts::aggOnly)) {
				*streams[0] << it->second->getSendAckTimeDiff(this) << endl;
				if (num_retr_tmp <= GlobOpts::max_retrans_stats)
					*streams[num_retr_tmp] << it->second->getSendAckTimeDiff(this) << endl;
			}
		}
	}

	for (unsigned long int i = 0; i < streams.size(); i++) {
		streams[i]->close();
		delete streams[i];
	}
}
