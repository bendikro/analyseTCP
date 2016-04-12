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

/**
 * This function generates the relative sequence number of packets read from pcap files.
 *
 * seq:                The sequence number of the packet
 * firstSeq:           The first sequence number in the stream
 * largestSeq:         The largest relative sequence number that has been read for this stream
 * largestSeqAbsolute: The largest absolute (raw) sequence number that has been read for this stream
 *
 * Returns the relative sequence number or std::numeric_limits<ulong>::max() if it failed.
 **/
seq64_t getRelativeSequenceNumber(seq32_t seq, seq32_t firstSeq, seq64_t largestSeq, seq32_t largestSeqAbsolute, Connection *conn) {
	ullint_t wrap_index;
	seq64_t seq_relative;
	wrap_index = firstSeq + largestSeq;
	wrap_index += 1;

	//printf("getRelativeSequenceNumber: seq: %u, firstSeq: %u, largestSeq: %llu, largestSeqAbsolute: %u, wrap_index: %llu\n", seq, firstSeq, largestSeq, largestSeqAbsolute, wrap_index);
	// Either seq has wrapped, or a retrans (or maybe reorder if netem is run on sender machine)
	if (seq < largestSeqAbsolute) {
		// This is an earlier sequence number
		if (before(seq, largestSeqAbsolute)) {
			if (before(seq, firstSeq)) {
				return std::numeric_limits<ulong>::max();
				//printf("Before first!\n");
			}
			wrap_index -= (largestSeqAbsolute - seq);
		}
		// Sequence number has wrapped
		else {
			wrap_index += (0 - largestSeqAbsolute) + seq;
		}
	}
	// When seq is greater, it is either newer data, or it is older data because
	// largestSeqAbsolute just wrapped. E.g. largestSeqAbsolute == 10, and seq = 4294967250
	else {
		//printf("wrap_index: %lu\n", wrap_index);
		// This is newer seq
		if (after_or_equal(largestSeqAbsolute, seq)) {
			//printf("after_or_equal\n");
			wrap_index += (seq - largestSeqAbsolute);
			//printf("new wrap_index: %lu\n", wrap_index);
		}
		// Acks older data than largestAckSeqAbsolute, largestAckSeqAbsolute has wrapped.
		else {
			wrap_index -= ((0 - seq) + largestSeqAbsolute);
		}
	}

	wrap_index /= 4294967296L;
	// When seq has wrapped, wrap_index will make sure the relative sequence number continues to grow
	seq_relative = seq + (wrap_index * 4294967296L) - firstSeq;
	if (seq_relative > 9999999999) {// TODO: Do a better check than this, e.g. checking for distance of largestSeq and seq_relative > a large number
		// use stderr for error messages for crying out loud!!!!!
		//fprintf(stderr, "wrap_index: %lu\n", wrap_index);
		//fprintf(stderr, "\ngetRelativeSequenceNumber: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u\n", seq, firstSeq, largestSeq, largestSeqAbsolute);
		//fprintf(stderr, "seq_relative: %lu\n", seq_relative);
		//fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());

#if !defined(NDEBUG)
		fprintf(stderr, "Encountered invalid sequence number for connection %s: %u (firstSeq=%u, largestSeq=%llu, largestSeqAbsolute=%u\n",
				conn->getConnKey().c_str(),
				seq,
				firstSeq,
				largestSeq,
				largestSeqAbsolute);
#endif

		//assert(0 && "Incorrect sequence number calculation!\n");
		return std::numeric_limits<ulong>::max();
	}
	//printf("RETURN seq_relative: %llu\n", seq_relative);
	return seq_relative;
}

seq64_t Connection::getRelativeSequenceNumber(seq32_t seq, relative_seq_type type) {
	switch (type) {
	case RELSEQ_SEND_OUT: // sender outgoing seq
		return ::getRelativeSequenceNumber(seq, rm->firstSeq, lastLargestEndSeq, lastLargestSeqAbsolute, this);
	case RELSEQ_SEND_ACK: // sender incomming (ack) seq
		return ::getRelativeSequenceNumber(seq, rm->firstSeq, lastLargestAckSeq, lastLargestAckSeqAbsolute, this);
	case RELSEQ_RECV_INN: // receiver incomming seq
		return ::getRelativeSequenceNumber(seq, rm->firstSeq, lastLargestRecvEndSeq, lastLargestRecvSeqAbsolute, this);
	case RELSEQ_SOJ_SEQ: // sojourn time seq
		return ::getRelativeSequenceNumber(seq, rm->firstSeq, lastLargestSojournEndSeq, lastLargestSojournSeqAbsolute, this);
	case RELSEQ_NONE: // sender outgoing seq
		break;
	}
	return std::numeric_limits<ulong>::max();
}


uint32_t Connection::getDuration(bool analyse_range_duration) {
	double d;
	if (analyse_range_duration) {
		d = getTimeInterval(rm->analyse_range_start->second, rm->analyse_range_last->second);
	}
	else {
		d = rm->getDuration();
	}
	return static_cast<uint32_t>(d);
}

/* Count bundled and retransmitted packets from sent data */
bool Connection::registerSent(sendData* sd) {
	totPacketSize += sd->totalSize;
	nrPacketsSent++;
#ifdef DEBUG
	int debug = 0;
#endif

	if (sd->data.endSeq > lastLargestEndSeq && lastLargestEndSeq +1 != sd->data.seq) {
#ifdef DEBUG
		if (debug) {
			colored_fprintf(stderr, RED, "CONN: %s\nSending unexpected sequence number: %llu, lastlargest: %llu\n",
							getConnKey().c_str(), sd->data.seq, lastLargestEndSeq);
		}
#endif
		if (closed) {
			ignored_count++;
			return false;
		}

		// For some reason, seq can increase even if no data was sent, some issue with multiple SYN packets.
		// 2014-08-12: This is expected for SYN retries after timeout (aka new connections)
		if (sd->data.flags & TH_SYN) {

			if (std::labs(sd->data.seq_absolute - rm->firstSeq) > 10) {
				colored_fprintf(stderr, RED, "New SYN changes sequence number by more than 10 (%ld) on connection with %ld ranges already registered.\n"
								"This is presumably due to TCP port number reused for a new connection. "
								"Marking this connection as closed and ignore any packets in the new connection.\n",
								std::labs(sd->data.seq_absolute - rm->firstSeq), rm->ranges.size());
				closed = true;
			}
			else {
				rm->firstSeq = sd->data.seq_absolute;
				//printf("Changing SD seq from (%llu - %llu) to (%d - %d)\n", sd->data.seq, sd->data.endSeq, 0, 0);
				sd->data.seq = 0;
				sd->data.endSeq = 0;
			}
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
		printf("\nRegisterSent (%llu): %s\n", (sd->data.endSeq - sd->data.seq),
		rm->absolute_seq_pair_str(sd->data.seq, END_SEQ(sd->data.endSeq)).c_str());
	}
#endif

	if (sd->data.endSeq > lastLargestEndSeq) { /* New data */
		if (DEBUGL_SENDER(6)) {
			printf("New Data - sd->endSeq: %llu > lastLargestEndSeq: %llu, sd->seq: %llu, lastLargestStartSeq: %llu, len: %u\n",
				   rm->get_print_seq(END_SEQ(sd->data.endSeq)),
				   rm->get_print_seq(END_SEQ(lastLargestEndSeq)),
				   rm->get_print_seq(sd->data.seq),
				   rm->get_print_seq(lastLargestStartSeq),
				   sd->data.payloadSize);
		}
#ifdef DEBUG
		if (debug) {
			printf("sd->data.seq:    %llu\n", rm->get_print_seq(sd->data.seq));
			printf(" lastLargestStartSeq:    %llu\n", rm->get_print_seq(lastLargestStartSeq));
			printf("sd->data.endSeq: %llu\n", rm->get_print_seq(END_SEQ(sd->data.endSeq)));
			printf("lastLargestEndSeq: %llu\n", rm->get_print_seq(END_SEQ(lastLargestEndSeq)));

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
	} else if (lastLargestStartSeq > 0 && sd->data.endSeq <= lastLargestStartSeq) { /* All seen before */
		if (DEBUGL_SENDER(6)) {
			printf("\nRetrans - lastLargestStartSeq: %llu > 0 && sd->data.seq: %llu <= lastLargestStartSeq: %llu\n",
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
		if (DEBUGL_SENDER(6)) {
			printf("Retrans - lastLargestStartSeq: %llu > 0 && sd->data.seq: %llu <= lastLargestStartSeq: %llu\n",
				   rm->get_print_seq(lastLargestStartSeq), rm->get_print_seq(sd->data.seq), rm->get_print_seq(lastLargestStartSeq));
			printf("New Data - sd->data.endSeq: %llu > lastLargestEndSeq: %llu\n",
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
void Connection::registerRange(sendData* sd) {
	if (DEBUGL_SENDER(4)) {
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

	if (DEBUGL_SENDER(4)) {
		cerr << "Last range: seq: " << rm->get_print_seq(rm->getLastRange()->getStartSeq())
		     << " - " << rm->get_print_seq(END_SEQ(rm->getLastRange()->getEndSeq())) << " - size: "
		     << rm->getLastRange()->getEndSeq() - rm->getLastRange()->getStartSeq() << endl;
	}
}

/* Register times for first ACK of each byte */
bool Connection::registerAck(DataSeg *seg) {
	static bool ret;
	if (DEBUGL_SENDER(4)) {
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

	if (DEBUGL_SENDER(4)) {
		if (rm->getHighestAcked() != NULL) {
			cerr << "highestAcked: startSeq: " << rm->get_print_seq(rm->getHighestAcked()->getStartSeq()) << " - endSeq: "
			     << rm->get_print_seq(rm->getHighestAcked()->getEndSeq()) << " - size: "
			     << rm->getHighestAcked()->getEndSeq() - rm->getHighestAcked()->getStartSeq() << endl;
		}
	}
	return ret;
}

void Connection::calculateRetransAndRDBStats() {
	setAnalyseRangeInterval();
	rm->calculateRetransAndRDBStats();
}

// Set which ranges to analyse
void Connection::setAnalyseRangeInterval() {
	ulong start_index = 0;
	rm->analyse_range_start = rm->ranges.begin();
	rm->analyse_range_end = rm->ranges.end();
	rm->analyse_range_last = rm->analyse_range_end;
	rm->analyse_range_last--;
	rm->analyse_time_sec_start = GlobOpts::analyse_start;

	timeval tv;
	timersub(&(rm->ranges.rbegin()->second->sent_tstamp_pcap[0].first),
			 &rm->analyse_range_start->second->sent_tstamp_pcap[0].first, &tv);
	rm->analyse_time_sec_end = tv.tv_sec;

	if (GlobOpts::analyse_start) {
		map<seq64_t, ByteRange*>::iterator it, it_end;
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
		multimap<seq64_t, ByteRange*>::reverse_iterator rit, rit_end = rm->ranges.rend();
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
		map<seq64_t, ByteRange*>::iterator begin_it, end_it, tmp_it;
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

	if ((rm->analysed_bytes_sent - getNumUniqueBytes()) != rm->analysed_redundant_bytes) {
		if (rm->analysed_bytes_sent >= getNumUniqueBytes()) {
			if (DEBUGL_SENDER(1)) {
				colored_fprintf(stderr, RED, "Mismatch between redundant bytes and (bytes_sent - UniqueBytes) which should be equal\n");
				fprintf(stderr, "CONNKEY: %s\n", getConnKey().c_str());
				fprintf(stderr, "rm->analysed_bytes_sent - getNumUniqueBytes (%llu) != rm->analysed_redundant_bytes (%llu)\n",
					   rm->analysed_bytes_sent - getNumUniqueBytes(), rm->analysed_redundant_bytes);
				fprintf(stderr, "rm->analysed_bytes_sent: %llu\n", rm->analysed_bytes_sent);
				fprintf(stderr, "getNumUniqueBytes(): %llu\n", getNumUniqueBytes());
				fprintf(stderr, "rm->analysed_redundant_bytes: %llu\n", rm->analysed_redundant_bytes);
				fprintf(stderr, "cs->totBytesSent: %llu\n", cs->totBytesSent);
				fprintf(stderr, "cs->totUniqueBytes: %llu\n", cs->totUniqueBytes);
				fprintf(stderr, "cs->totBytesSent - cs->totUniqueBytes: %llu\n", cs->totBytesSent - cs->totUniqueBytes);
			}
		}
	}
	cs->rdb_packet_misses += rm->rdb_packet_misses;
	cs->rdb_packet_hits += rm->rdb_packet_hits;
	cs->rdb_byte_misses += rm->rdb_byte_miss;
	cs->rdb_byte_hits += rm->rdb_byte_hits;
}

/* Generate statistics for bytewise latency */
void Connection::genBytesLatencyStats(PacketsStats* bs) {
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
void Connection::validateRanges() {
	if (DEBUGL(2)) {
		cerr << "###### Validation of range data ######" << endl;
		cerr << "Connection: " << getConnKey() << endl;
	}
	rm->validateContent();
}

void Connection::registerRecvd(sendData *sd) {
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

ullint_t Connection::getNumUniqueBytes() {
	multimap<seq64_t, ByteRange*>::iterator it, it_end;
	it = rm->analyse_range_start;
	it_end = rm->analyse_range_end;
	seq64_t first_data_seq = 0, last_data_seq = 0;
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

void Connection::registerPacketSize(const timeval& first, const timeval& ts, const uint32_t ps, const uint16_t payloadSize) {
	const uint64_t relative_ts = static_cast<uint64_t>(TV_TO_MS(ts) - TV_TO_MS(first));
	const uint64_t sent_time_bucket_idx = relative_ts / GlobOpts::throughputAggrMs;

	while (sent_time_bucket_idx >= packetSizes.size()) {
		vector< PacketSize> empty;
		packetSizes.push_back(empty);
		PacketSizeGroup empty2;
		packetSizeGroups.push_back(empty2);
	}
	PacketSize pSize(ts, static_cast<uint16_t>(ps), payloadSize);
	packetSizes[sent_time_bucket_idx].push_back(pSize);
	packetSizeGroups[sent_time_bucket_idx].add(pSize);
}

void Connection::writePacketByteCountAndITT(vector<csv::ofstream*> streams) {
	size_t i, j;

	uint64_t k = 0;
	while (packetSizes[k].empty()) k++;

	int64_t prev = TV_TO_MICSEC(packetSizes[k][0].time);
	int64_t itt, tmp;
	for (i = 0; i < packetSizes.size(); ++i) {
		for (j = 0; j < packetSizes[i].size(); ++j) {
			tmp = TV_TO_MICSEC(packetSizes[i][j].time);
			itt = (tmp - prev) / 1000L;
			prev = tmp;

			for (csv::ofstream* stream : streams) {
				*stream << tmp << itt << packetSizes[i][j].payload_size << packetSizes[i][j].packet_size << NEWLINE;
            }
		}
	}
}
