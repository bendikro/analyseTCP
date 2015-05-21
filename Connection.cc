#include "Connection.h"
#include "ByteRange.h"
#include "util.h"
#include "color_print.h"

ofstream& operator<<(ofstream& stream, const PacketSizeGroup& psGroup) {
	stream << psGroup.str();
	return stream;
}


string PacketSizeGroup::str() const {
	ostringstream buffer;
	buffer << packetSizes.size() << "," << bytes;
	return buffer.str();
}

uint32_t Connection::getDuration(bool analyse_range_duration) {
	if (analyse_range_duration)
		return getTimeInterval(rm->analyse_range_start->second, rm->analyse_range_last->second);
	else
		return rm->getDuration();
}

/* Count bundled and retransmitted packets from sent data */
bool Connection::registerSent(struct sendData* sd) {
	totPacketSize += sd->totalSize;
	nrPacketsSent++;
#ifdef DEBUG
	int debug = 0;
#endif

	if (sd->data.endSeq > lastLargestEndSeq && lastLargestEndSeq +1 != sd->data.seq) {
#ifdef DEBUG
		if (debug) {
			printf("CONN: %s\n", getConnKey().c_str());
			colored_printf(RED, "Sending unexpected sequence number: %lu, lastlargest: %lu\n",
						   sd->data.seq, lastLargestEndSeq);
		}
#endif
		// For some reason, seq can increase even if no data was sent, some issue with multiple SYN packets.
		// 2014-08-12: This is expected for SYN retries after timeout (aka new connections)
		if (sd->data.flags & TH_SYN) {
			//printf("Changing firstSeq from %u to %u\n", rm->firstSeq, sd->data.seq_absolute);
			rm->firstSeq = sd->data.seq_absolute;
			//printf("Changing SD seq from (%lu - %lu) to (%d - %d)\n", sd->data.seq, sd->data.endSeq, 0, 0);
			sd->data.seq = 0;
			sd->data.endSeq = 0;
		}
	}

	// This is ack
	if (sd->data.payloadSize == 0) {
		if (sd->data.flags & TH_RST) {
			//printf("CONN: %s\n", getConnKey().c_str());
			//assert("RST!" && 0);
			//return false;
			return true;
		}
		else
			return true;
	}

#ifdef DEBUG
	if (debug) {
		printf("\nRegisterSent (%lu): %s\n",
               (ulong)(sd->data.endSeq - sd->data.seq),
		       rm->relative_seq_pair_str(sd->data.seq, END_SEQ(sd->data.endSeq)).c_str());
	}
#endif
	//printf("lastLargestEndSeq: %lu\n", lastLargestEndSeq);


	if (sd->data.endSeq > lastLargestEndSeq) { /* New data */
		if (GlobOpts::debugLevel == 6) {
			printf("New Data - sd->endSeq: %lu > lastLargestEndSeq: %lu, sd->seq: %lu, lastLargestStartSeq: %lu, len: %u\n",
				   rm->get_print_seq(END_SEQ(sd->data.endSeq)),
				   rm->get_print_seq(END_SEQ(lastLargestEndSeq)),
				   rm->get_print_seq(sd->data.seq),
				   rm->get_print_seq(lastLargestStartSeq),
				   sd->data.payloadSize);
		}
#ifdef DEBUG
		if (debug) {
			printf("sd->data.seq:    %lu\n", rm->get_print_seq(sd->data.seq));
			printf(" lastLargestStartSeq:    %lu\n", rm->get_print_seq(lastLargestStartSeq));
			printf("sd->data.endSeq: %lu\n", rm->get_print_seq(END_SEQ(sd->data.endSeq)));
			printf("lastLargestEndSeq: %lu\n", rm->get_print_seq(END_SEQ(lastLargestEndSeq)));

			printf("(sd->data.seq == lastLargestStartSeq): %d\n", (sd->data.seq == lastLargestStartSeq));
			printf("(sd->data.endSeq > lastLargestEndSeq): %d\n", (sd->data.endSeq > lastLargestEndSeq));
			printf("(sd->data.seq > lastLargestStartSeq): %d\n", (sd->data.seq > lastLargestStartSeq));
			printf("(sd->data.seq < lastLargestEndSeq): %d\n", (sd->data.seq < lastLargestEndSeq));
			printf("(sd->data.endSeq > lastLargestEndSeq): %d\n", (sd->data.endSeq > lastLargestEndSeq));
		}
#endif
		// Same seq as previous packet, if (lastLargestStartSeq + lastLargestEndSeq) == 0, it's the first packet of a stream with no SYN
		if ((sd->data.seq == lastLargestStartSeq) && (sd->data.endSeq > lastLargestEndSeq)
			&& (lastLargestStartSeq + lastLargestEndSeq) != 0) {
			bundleCount++;
			totRDBBytesSent += (lastLargestEndSeq - sd->data.seq);
			totNewDataSent += (sd->data.endSeq - lastLargestEndSeq);
			sd->data.is_rdb = true;
			sd->data.rdb_end_seq = lastLargestEndSeq;
		} else if ((sd->data.seq > lastLargestStartSeq) && (sd->data.seq < lastLargestEndSeq)
				   && (sd->data.endSeq > lastLargestEndSeq)) {
			totRDBBytesSent += (lastLargestEndSeq - sd->data.seq);
			totNewDataSent += (sd->data.endSeq - lastLargestEndSeq);
			bundleCount++;
			sd->data.is_rdb = true;
			sd->data.rdb_end_seq = lastLargestEndSeq;
		} else if ((sd->data.seq < lastLargestEndSeq) && (sd->data.endSeq > lastLargestEndSeq)) {
			totRDBBytesSent += (lastLargestEndSeq - sd->data.seq);
			totNewDataSent += (sd->data.endSeq - lastLargestEndSeq);
			bundleCount++;
			sd->data.is_rdb = true;
			sd->data.rdb_end_seq = lastLargestEndSeq;
		}
		else {
			// New data that is not RDB
			totNewDataSent += sd->data.payloadSize;
		}
		lastLargestEndSeq = sd->data.endSeq;
		lastLargestSeqAbsolute = sd->data.seq_absolute + sd->data.payloadSize;
	} else if (lastLargestStartSeq > 0 && sd->data.seq <= lastLargestStartSeq) { /* All seen before */
		if (GlobOpts::debugLevel == 6) {
			printf("\nRetrans - lastLargestStartSeq: %lu > 0 && sd->data.seq: %lu <= lastLargestStartSeq: %lu\n",
				   rm->get_print_seq(lastLargestStartSeq), rm->get_print_seq(sd->data.seq),
				   rm->get_print_seq(lastLargestStartSeq));
		}
		nrRetrans++;
		totRetransBytesSent += sd->data.payloadSize;
		sd->data.retrans = true;
	}
	else {
		nrRetrans++;
		totRetransBytesSent += sd->data.payloadSize;
		sd->data.retrans = true;
		if (GlobOpts::debugLevel == 6) {
			printf("Retrans - lastLargestStartSeq: %lu > 0 && sd->data.seq: %lu <= lastLargestStartSeq: %lu\n",
				   rm->get_print_seq(lastLargestStartSeq), rm->get_print_seq(sd->data.seq), rm->get_print_seq(lastLargestStartSeq));
			printf("New Data - sd->data.endSeq: %lu > lastLargestEndSeq: %lu\n",
				   rm->get_print_seq(END_SEQ(sd->data.endSeq)), rm->get_print_seq(END_SEQ(lastLargestEndSeq)));
		}
	}

	if (sd->data.payloadSize) {
		nrDataPacketsSent++;
		lastLargestStartSeq = sd->data.seq;
	}
	totBytesSent += sd->data.payloadSize;
	return true;
}

/* Process range for outgoing packet */
void Connection::registerRange(struct sendData* sd) {
	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
		if (firstSendTime.tv_sec == 0 && firstSendTime.tv_usec == 0) {
			firstSendTime = sd->data.tstamp_pcap;
		}

		timeval offset;
		timersub(&(sd->data.tstamp_pcap), &firstSendTime, &offset);
		cerr << "\nRegistering new outgoing. Seq: " << rm->get_print_seq(sd->data.seq) << " - "
		     << rm->get_print_seq(END_SEQ(sd->data.endSeq)) << " Absolute seq: " << sd->data.seq << " - "
			 << END_SEQ(sd->data.endSeq) << " Payload: " << sd->data.payloadSize << endl;
		cerr << "Time offset: Secs: " << offset.tv_sec << "." << offset.tv_usec << endl;
	}

	rm->insertSentRange(sd);

	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
		cerr << "Last range: seq: " << rm->get_print_seq(rm->getLastRange()->getStartSeq())
		     << " - " << rm->get_print_seq(END_SEQ(rm->getLastRange()->getEndSeq())) << " - size: "
		     << rm->getLastRange()->getEndSeq() - rm->getLastRange()->getStartSeq() << endl;
	}
}

/* Register times for first ACK of each byte */
bool Connection::registerAck(struct DataSeg *seg) {
	static bool ret;
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		timeval offset;
		timersub(&seg->tstamp_pcap, &firstSendTime, &offset);
		cerr << endl << "Registering new ACK. Conn: " << getConnKey() << " Ack: " << rm->get_print_seq(seg->ack) << endl;
		cerr << "Time offset: Secs: " << offset.tv_sec << " uSecs: " << offset.tv_usec << endl;
	}

	ret = rm->processAck(seg);
	if (ret) {
		lastLargestAckSeq = seg->endSeq;
		lastLargestAckSeqAbsolute = seg->seq_absolute + seg->payloadSize;
	}

	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		if(rm->getHighestAcked() != NULL){
			cerr << "highestAcked: startSeq: " << rm->get_print_seq(rm->getHighestAcked()->getStartSeq()) << " - endSeq: "
			     << rm->get_print_seq(rm->getHighestAcked()->getEndSeq()) << " - size: "
			     << rm->getHighestAcked()->getEndSeq() - rm->getHighestAcked()->getStartSeq() << endl;
		}
	}
	return ret;
}

void Connection::calculateRetransAndRDBStats() {
	set_analyse_range_interval();
	rm->calculateRetransAndRDBStats();
}

// Set which ranges to analyse
void Connection::set_analyse_range_interval() {
	ulong start_index = 0;
	rm->analyse_range_start = rm->ranges.begin();
	rm->analyse_range_end = rm->ranges.end();
	rm->analyse_range_last = rm->analyse_range_end;
	rm->analyse_range_last--;
	rm->analyse_time_sec_start = GlobOpts::analyse_start;

	struct timeval tv;
	timersub(&(rm->ranges.rbegin()->second->sent_tstamp_pcap[0].first),
			 &rm->analyse_range_start->second->sent_tstamp_pcap[0].first, &tv);
	rm->analyse_time_sec_end = tv.tv_sec;

	if (GlobOpts::analyse_start) {
		map<ulong, ByteRange*>::iterator it, it_end;
		it = rm->ranges.begin();
		timeval first_pcap_tstamp = it->second->sent_tstamp_pcap[0].first;
		it_end = rm->ranges.end();
		for (; it != it_end; it++) {
			timersub(&(it->second->sent_tstamp_pcap[0].first), &first_pcap_tstamp, &tv);
			if (tv.tv_sec >= GlobOpts::analyse_start) {
				rm->analyse_range_start = it;
				rm->analyse_time_sec_start = tv.tv_sec;
				break;
			}
			start_index++;
		}
	}

	if (GlobOpts::analyse_end) {
		multimap<ulong, ByteRange*>::reverse_iterator rit, rit_end = rm->ranges.rend();
		rit = rm->ranges.rbegin();
		timeval last_pcap_tstamp = rit->second->sent_tstamp_pcap[0].first;
		rit_end = rm->ranges.rend();
		for (; rit != rit_end; rit++) {
			timersub(&last_pcap_tstamp, &(rit->second->sent_tstamp_pcap[0].first), &tv);
			if (tv.tv_sec >= GlobOpts::analyse_end) {
				rm->analyse_range_last = rm->analyse_range_end = rit.base();
				rm->analyse_range_end++;
				timersub(&(rit->second->sent_tstamp_pcap[0].first),
						 &rm->ranges.begin()->second->sent_tstamp_pcap[0].first, &tv);
				rm->analyse_time_sec_end = tv.tv_sec;
				break;
			}
		}
	}
	else if (GlobOpts::analyse_duration) {
		ulong end_index = rm->ranges.size();
		timeval begin_tv = rm->analyse_range_start->second->sent_tstamp_pcap[0].first;
		map<ulong, ByteRange*>::iterator begin_it, end_it, tmp_it;
		begin_it = rm->analyse_range_start;
		end_it = rm->ranges.end();
		while (true) {
			ulong advance = (end_index - start_index) / 2;
			// We have found the transition point
			if (!advance) {
				rm->analyse_range_end = rm->analyse_range_last = begin_it;
				rm->analyse_range_end++;
				timersub(&(begin_it->second->sent_tstamp_pcap[0].first), &begin_tv, &tv);
				rm->analyse_time_sec_end = rm->analyse_time_sec_start + GlobOpts::analyse_duration;
				break;
			}

			tmp_it = begin_it;
			std::advance(tmp_it, advance);

			timersub(&(tmp_it->second->sent_tstamp_pcap[0].first), &begin_tv, &tv);
			// Compares seconds, does not take into account milliseconds
			// Shorter than the requested length
			if (tv.tv_sec <= GlobOpts::analyse_duration) {
				begin_it = tmp_it;
				start_index += advance;
			}
			// Longer than the requested length
			else if (tv.tv_sec > GlobOpts::analyse_duration) {
				end_index -= advance;
			}
		}
	}
	rm->analysed_ranges_count = std::distance(rm->analyse_range_start, rm->analyse_range_end);
}

/* Generate statistics for each connection.
   update aggregate stats if requested */
void Connection::addConnStats(ConnStats* cs) {
	cs->duration += getDuration(true);
	cs->analysed_duration_sec += rm->analyse_time_sec_end - rm->analyse_time_sec_start;
	cs->analysed_start_sec += rm->analyse_time_sec_start;
	cs->analysed_end_sec += rm->analyse_time_sec_end;
	cs->totBytesSent += rm->analysed_bytes_sent;
	cs->totRetransBytesSent += rm->analysed_bytes_retransmitted;
	cs->nrPacketsSent += rm->analysed_packet_sent_count;
	cs->nrPacketsSentFoundInDump += rm->analysed_packet_sent_count_in_dump;
	cs->nrPacketsReceivedFoundInDump += rm->analysed_packet_received_count;
	cs->nrDataPacketsSent += rm->analysed_data_packet_count;
	cs->nrRetrans += rm->analysed_retr_packet_count;
	cs->nrRetransNoPayload += rm->analysed_retr_no_payload_packet_count;
	cs->bundleCount += rm->analysed_rdb_packet_count;
	cs->totUniqueBytes += getNumUniqueBytes();
	cs->totUniqueBytesSent += rm->analysed_bytes_sent_unique;
	cs->redundantBytes += rm->getRedundantBytes();
	cs->rdb_bytes_sent += rm->rdb_byte_miss + rm->rdb_byte_hits;
	cs->ackCount += rm->analysed_ack_count;
	cs->synCount += rm->analysed_syn_count;
	cs->finCount += rm->analysed_fin_count;
	cs->rstCount += rm->analysed_rst_count;
	cs->pureAcksCount += rm->analysed_pure_acks_count;

	cs->ranges_sent += rm->getByteRangesSent();
	cs->ranges_lost += rm->getByteRangesLost();
	cs->bytes_lost += rm->getLostBytes();
	cs->totPacketSize += totPacketSize;

#ifdef DEBUG
	if ((rm->analysed_bytes_sent - getNumUniqueBytes()) != rm->analysed_redundant_bytes) {
		if (rm->analysed_bytes_sent >= getNumUniqueBytes()) {
			colored_printf(RED, "Mismatch between redundant bytes and (bytes_sent - UniqueBytes) which should be equal\n");
			printf("CONNKEY: %s\n", getConnKey().c_str());
			printf("rm->analysed_bytes_sent - getNumUniqueBytes (%lu) != rm->analysed_redundant_bytes (%lu)\n",
				   rm->analysed_bytes_sent - getNumUniqueBytes(), rm->analysed_redundant_bytes);
			printf("rm->analysed_bytes_sent: %lu\n", rm->analysed_bytes_sent);
			printf("getNumUniqueBytes(): %lu\n", getNumUniqueBytes());
			printf("rm->analysed_redundant_bytes: %lu\n", rm->analysed_redundant_bytes);
			printf("cs->totBytesSent: %lu\n", cs->totBytesSent);
			printf("cs->totUniqueBytes: %lu\n", cs->totUniqueBytes);
			printf("cs->totBytesSent - cs->totUniqueBytes: %lu\n", cs->totBytesSent - cs->totUniqueBytes);
		}
	}
//	assert("Redundant bytes mismatch" && (rm->analysed_bytes_sent - getNumUniqueBytes()) == rm->analysed_redundant_bytes);
#endif
	cs->rdb_packet_misses += rm->rdb_packet_misses;
	cs->rdb_packet_hits += rm->rdb_packet_hits;
	cs->rdb_byte_misses += rm->rdb_byte_miss;
	cs->rdb_byte_hits += rm->rdb_byte_hits;
}

/* Generate statistics for bytewise latency */
void Connection::genBytesLatencyStats(PacketsStats* bs){
	rm->genStats(bs);
}

PacketsStats* Connection::getBytesLatencyStats() {
	if (!packetsStats.has_stats()) {
		packetsStats.init();
		rm->genStats(&packetsStats);
	}
	return &packetsStats;
}

/* Check validity of connection range and time data */
void Connection::validateRanges(){
	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
		cerr << "###### Validation of range data ######" << endl;
		cerr << "Connection: " << getConnKey() << endl;
	}
	rm->validateContent();
	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
		cerr << "Validation successful." << endl;
		cerr << "###### End of validation ######" << endl;
	}
}

void Connection::registerRecvd(struct sendData *sd) {
	/* Insert range into datastructure */
	if (sd->data.seq <= lastLargestRecvEndSeq &&
		sd->data.endSeq > lastLargestRecvEndSeq) {
		sd->data.in_sequence = 1;
	}

	rm->insertReceivedRange(sd);
	lastLargestRecvEndSeq = sd->data.endSeq;
	lastLargestRecvSeqAbsolute = sd->data.seq_absolute + sd->data.payloadSize;
}

void Connection::writeByteLatencyVariationCDF(ofstream *stream) {
	*stream << endl;
	*stream << "#------CDF - Conn: " << getConnKey() << " --------" << endl;
	rm->writeByteLatencyVariationCDF(stream);
}

ulong Connection::getNumUniqueBytes() {
	multimap<ulong, ByteRange*>::iterator it, it_end;
	it = rm->analyse_range_start;
	it_end = rm->analyse_range_end;
	ulong first_data_seq = 0, last_data_seq = 0;
	for (; it != it_end; it++) {
		if (it->second->getNumBytes()) {
			first_data_seq = it->second->getStartSeq();
			break;
		}
	}

	it_end = rm->analyse_range_start;
	it = rm->analyse_range_last;
	for (; it != it_end; it--) {
		if (it->second->getNumBytes()) {
			last_data_seq = it->second->getEndSeq();
			break;
		}
	}
	ulong unique_data_bytes = last_data_seq - first_data_seq;
	return unique_data_bytes;
}

void Connection::registerPacketSize(const timeval& first, const timeval& ts, const uint64_t ps, const uint16_t payloadSize) {
	const uint64_t relative_ts = TV_TO_MS(ts) - TV_TO_MS(first);
	const uint64_t sent_time_bucket_idx = relative_ts / GlobOpts::throughputAggrMs;

	while (sent_time_bucket_idx >= packetSizes.size()) {
		vector< PacketSize> empty;
		packetSizes.push_back(empty);
		PacketSizeGroup empty2;
		packetSizeGroups.push_back(empty2);
	}
	PacketSize pSize(ts, ps, payloadSize);
	packetSizes[sent_time_bucket_idx].push_back(pSize);
	packetSizeGroups[sent_time_bucket_idx].add(pSize);
}

void Connection::writePacketByteCountAndITT(vector<ofstream*> streams) {
	size_t i, j;

	uint64_t k = 0;
	while (packetSizes[k].empty()) k++;

	uint64_t prev = TV_TO_MICSEC(packetSizes[k][0].time);
	uint64_t itt, tmp;
	for (i = 0; i < packetSizes.size(); ++i) {
		for (j = 0; j < packetSizes[i].size(); ++j) {
			tmp = TV_TO_MICSEC(packetSizes[i][j].time);
			itt = (tmp - prev) / 1000L;
			prev = tmp;

			for(ofstream* stream : streams) {
				*stream << tmp << "," << itt << "," << packetSizes[i][j].payload_size << "," << packetSizes[i][j].packet_size << endl;
            }
		}
	}
}
