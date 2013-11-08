#include "RangeManager.h"
#include "Connection.h"
#include "Range.h"
#include "ByteRange.h"
#include "analyseTCP.h"
#include "color_print.h"

map<const int, int> GlobStats::cdf;
map<const int, int> GlobStats::dcCdf;
float GlobStats::avgDrift = 0;

RangeManager::~RangeManager() {
	multimap<ulong, Range*>::iterator it, it_end;
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

	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt = brMap.begin();
	brIt_end = brMap.end();

	for (; brIt != brIt_end; brIt++) {
		delete brIt->second;
	}
}

bool RangeManager::hasReceiveData() {
	return !recvd.empty();
}

/* Register all bytes with a common send time as a range */
Range* RangeManager::insertSentRange(struct sendData *sd) {
	static ulong startSeq;
	static ulong endSeq;
	static timeval *tv;
	static Range* range;
	static int ranges_size;
	static multimap<ulong, Range*>::reverse_iterator it, it_end;

	startSeq = sd->data.seq;
	endSeq = sd->data.endSeq;
	tv = &(sd->data.tstamp_pcap);
	range = NULL;

	//printf("insertSentRange(%4d) (%u - %u)\n", sd->data.payloadSize, relative_seq(startSeq), relative_seq(endSeq));

	if (GlobOpts::debugLevel == 6) {
		printf("\ninsertSentRange - retrans: %d, is_rdb %d\n", sd->data.retrans, sd->data.is_rdb);
	}

	// Ignore acks (including SYN/ack and FIN/ack)
	if ((GlobOpts::print_packets || GlobOpts::rdbDetails) && startSeq != endSeq)
		insert_byte_range(startSeq, endSeq, true, &(sd->data), 0);

	ranges_size = ranges.size();
	if (ranges_size <= 1 && sd->data.payloadSize == 0) { /* First or second packet in stream */
		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
			cerr << "-------Creating first range---------" << endl;

		if (ranges_size == 0) {
			range = new Range(startSeq, startSeq, endSeq, sd->data.payloadSize, NULL, tv, false, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));
			lastSeq = 1;
		}
		else {
			lastSeq = endSeq;
		}
	}
	else if (startSeq == lastSeq) { /* Next packet in correct sequence */

		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
			cerr << "-------New range equivalent with packet---------" << endl;
			printf("%s - inserted Range with startseq: %lu\n", conn->getConnKey().c_str(), relative_seq(startSeq));
		}
		range = new Range(startSeq, startSeq, endSeq, sd->data.payloadSize, NULL, tv, false, this);
		ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));
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
	else if (!GlobOpts::incTrace && (startSeq > lastSeq) ) {
		// This is most probably the ack on the FIN ack from receiver, so ignore
		if (sd->data.payloadSize != 0) {
			cerr << "RangeManager::insertRange: Missing byte in send range in conn '" << conn->getConnKey() << "'. " << endl;
			printf("lastSeq: %lu, startSeq: %lu\n", relative_seq(lastSeq), relative_seq(startSeq));
			cerr << "This is an indication that tcpdump has dropped packets" << endl
			     << "while collecting the trace." << endl
			     << "Please rerun using the -b option." << endl;
			exit_with_file_and_linenum(1, __FILE__, __LINE__);
		}
	}

	/* If we have missing packets in the sender dump, insert a dummy range
	   before the new range. This range will not be used to generate statistics */
	else if (startSeq > lastSeq) {

		// This is an ack
		if (sd->data.payloadSize == 0) {
			range = new Range(startSeq, startSeq, endSeq, sd->data.payloadSize, NULL, tv, false, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));
			lastSeq = startSeq + sd->data.payloadSize;
		}
		else {

			/* Insert dummy range */
			if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
				cerr << "-------Missing packet(s): inserting dummy range---------" << endl;
				cerr << "Dummy range: lastSeq:  " << relative_seq(lastSeq) << " - startSeq: " << relative_seq(startSeq)
				     << " - size: " << relative_seq(startSeq +1 - lastSeq) << endl;
				cerr << "Valid range: startSeq: " << relative_seq(startSeq) << " - endSeq:   " << relative_seq(endSeq)
				     << " - size: " << relative_seq(endSeq +1 - startSeq ) << endl;
			}

			range = new Range(lastSeq, lastSeq, startSeq -1, startSeq - lastSeq, NULL, tv, true, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));

			/* Then insert the new, valid range */
			range = new Range(startSeq, startSeq, endSeq, sd->data.payloadSize, NULL, tv, false, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));

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
			/* Traverse all affected ranges and tag all
			   ranges that contain retransmitted bytes */
			it_end = ranges.rend();
			for (it = ranges.rbegin(); it != it_end; it++) {
				if (startSeq > it->second->getEndSeq())
					break;
				if ((endSeq + 1) > it->second->getStartSeq()) {
					it->second->incNumRetrans(); // Count a new retransmission
				}
			}
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

			range = new Range(lastSeq, lastSeq, endSeq, sd->data.payloadSize, NULL, tv, false, this);

			ranges.insert(pair<ulong, Range*>(range->getStartSeq(), range));
			lastSeq = startSeq + sd->data.payloadSize;
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->data.payloadSize);
			}

			/* Traverse all affected ranges and tag all
			   ranges that contain bundled bytes */
			it_end = ranges.rend();
			for (it = ranges.rbegin(); it != it_end; it++) {
				if (startSeq >= it->second->getEndSeq())
					break;
				if (endSeq > it->second->getStartSeq())
					it->second->incNumBundled(); /* Count a new bundling */
			}
		}
	}

	if ((startSeq + sd->data.payloadSize) > largestEndSeq) {
		largestEndSeq = startSeq + sd->data.payloadSize;
	}
	return range;
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

/* Register all bytes with a coomon send time as a range */
/*
void RangeManager::insertRecvRange(struct sendData *sd) {
	static struct recvData *tmpRecv;
	tmpRecv = new struct recvData();
	tmpRecv->startSeq = sd->data.seq;
	tmpRecv->endSeq = sd->data.endSeq;
	tmpRecv->tv = (sd->data.tstamp_pcap);
	tmpRecv->data = sd->data.data;
	tmpRecv->payload_len = sd->data.payloadSize;

	if (sd->data.payloadSize > 0)
		tmpRecv->endSeq -= 1;

	if (GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5) {
		cerr << "Inserting receive data: startSeq=" << relative_seq(tmpRecv->startSeq) << ", endSeq=" << relative_seq(tmpRecv->endSeq) << endl;
		if (tmpRecv->startSeq == 0 || tmpRecv->endSeq == 0) {
			cerr << "Erroneous seq." << endl;
		}
	}

	recvd.push_back(tmpRecv);

	std::ostringstream key;
	key << tmpRecv->startSeq << ":" << tmpRecv->endSeq;
	return;
}
*/
/*
long get_timeval(timeval* tv) {
	long ms = 0;
	if (tv->tv_sec > 0) {
		ms += tv->tv_sec * 1000;
	}
	ms += (tv->tv_usec / 1000);
	return ms;
}
*/

/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAck(ulong ack, timeval* tv) {
	static Range* tmpRange;
	static bool ret;
	static multimap<ulong, Range*>::iterator it, it_end;
	ret = false;
	it = ranges.begin();
	it_end = ranges.end();

	if (highestAckedIt == ranges.end()) {
		it = ranges.begin();
	}
	else {
		it = highestAckedIt;
	}

	for (; it != it_end; it++) {
		tmpRange = it->second;

		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "tmpRange - startSeq: " << relative_seq(tmpRange->getStartSeq())
			     << " - endSeq: " << relative_seq(tmpRange->getEndSeq()) << endl;

		/* All data from this ack has been acked before: return */
		if (ack <= tmpRange->getStartSeq()) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------All data has been ACKed before - skipping--------" << endl;
			ret = true;
			break;
		}

		/* This ack covers this range, but not more: ack and return */
		if (ack == (tmpRange->getEndSeq() + 1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack equivalent with last range --------" << endl;
			tmpRange->insertAckTime(tv);
			highestAckedIt = it;
			highestAckedIt++;
			return true;
		}

		/* ACK covers more than this range: ACK this range and continue */
		if (ack > (tmpRange->getEndSeq() +1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack covers more than this range: Continue to next --------" << endl;
			tmpRange->insertAckTime(tv);
			highestAckedIt = it;
			highestAckedIt++;
			ret = true;
			continue;
		}

		/* ACK covers only part of this range: split range and return */
		if (ack > tmpRange->getStartSeq() && ack < (tmpRange->getEndSeq() +1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
				cerr << "--------Ack covers only parts of this range: Splitting --------" << endl;
				cerr << " Split range dummy: " << tmpRange->isDummy() << endl;
				cerr << " Split range nr.retrans: " << tmpRange->getNumRetrans() << endl;
			}

			Range* newRange = new Range(ack, ack, tmpRange->getEndSeq(), tmpRange->getEndSeq() - ack + 1, NULL,
						    tmpRange->getSendTime(), tmpRange->isDummy(), this);

			/* First part of range: increase startSeq = ack + 1 no ack*/
			tmpRange->setEndSeq(ack - 1);
			if (tmpRange->getRDBSeq() > ack) {
				printf("RDB SEQ greater than ACK!\n");
			}

			if (relative_seq(tmpRange->getStartSeq()) == 1785761810) {
				printf("Set acktime for RANGE3!!\n");
			}


			tmpRange->insertAckTime(tv);
			/* Second part of range: insert before it (tmpRange) */
			highestAckedIt = ranges.insert(pair<ulong, Range*>(newRange->getStartSeq(), newRange));
			return true;
		}

		/* If we get here, something's gone wrong */
		cerr << "tmpRange->startSeq : " << relative_seq(tmpRange->getStartSeq()) << endl;
		cerr << "tmpRange->endSeq   : " << relative_seq(tmpRange->getEndSeq()) << endl;
		cerr << "ack                : " << relative_seq(ack) << endl;
		cerr << "RangeManager::processAck: Error in ack processing. Exiting." << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	if (!ret)
		printf("ACK failed to find packet!\n");

	return ret;
}

/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAckByteRange(ulong ack, timeval* tv) {
	static ByteRange* tmpRange;
	static bool ret;
	int debug_print = 0;
	static multimap<ulong, ByteRange*>::iterator it, it_end;
	ret = false;
	it = brMap.begin();
	it_end = brMap.end();

	if (highestAckedByteRangeIt == brMap.end()) {
		it = brMap.begin();
	}
	else {
		it = highestAckedByteRangeIt;
	}

//	debug_print = GlobOpts::debugLevel == 6;

	if (relative_seq(ack) >= 3921820430 && relative_seq(ack) <= 3921859425) {
		debug_print = 1;
	}


	if (debug_print)
		printf("ProcessACK: %lu\n", relative_seq(ack));

	for (; it != it_end; it++) {
		tmpRange = it->second;

		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "tmpRange - startSeq: " << relative_seq(tmpRange->getStartSeq())
			     << " - endSeq: " << relative_seq(tmpRange->getEndSeq()) << endl;

		/* All data from this ack has been acked before: return */
		if (ack <= tmpRange->getStartSeq()) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------All data has been ACKed before - skipping--------" << endl;
			if (debug_print)
				printf("  All has been acked before\n");
			ret = true;
			break;
		}

		/* This ack covers this range, but not more: ack and return */
		if (ack == (tmpRange->getEndSeq() + 1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack equivalent with last range --------" << endl;
			if (debug_print)
				printf("  Covers just this Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));
			tmpRange->insertAckTime(tv);
			highestAckedByteRangeIt = it;
			highestAckedByteRangeIt++;
			return true;
		}

		/* ACK covers more than this range: ACK this range and continue */
		if (ack > (tmpRange->getEndSeq() +1)) {
			if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
				cerr << "--------Ack covers more than this range: Continue to next --------" << endl;
			if (debug_print)
				printf("  Covers more than Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));
			tmpRange->insertAckTime(tv);
			highestAckedByteRangeIt = it;
			highestAckedByteRangeIt++;
			ret = true;
			continue;
		}

		/* ACK covers only part of this range: split range and return */
		if (ack > tmpRange->getStartSeq() && ack < (tmpRange->getEndSeq() +1)) {
			//printf("ByteRange(%lu, %lu) - ack: %lu\n", tmpRange->getStartSeq(), tmpRange->getEndSeq(), ack);
			if (debug_print) {
				printf("  Covers parts of  Range(%lu, %lu)\n", relative_seq(tmpRange->getStartSeq()), relative_seq(tmpRange->getEndSeq()));
			}
			ByteRange *new_br = tmpRange->split_end(ack, tmpRange->endSeq);

			tmpRange->insertAckTime(tv);
            /*
			  if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
				cerr << "--------Ack covers only parts of this range: Splitting --------" << endl;
				cerr << " Split range dummy: " << tmpRange->isDummy() << endl;
				cerr << " Split range nr.retrans: " << tmpRange->getNumRetrans() << endl;
			}
			*/
			// Second part of range: insert after tmpRange (tmpRange)
			highestAckedByteRangeIt = brMap.insert(pair<ulong, ByteRange*>(new_br->getStartSeq(), new_br));
			return true;

		}

		/* If we get here, something's gone wrong */
		cerr << "tmpRange->startSeq : " << relative_seq(tmpRange->getStartSeq()) << endl;
		cerr << "tmpRange->endSeq   : " << relative_seq(tmpRange->getEndSeq()) << endl;
		cerr << "ack                : " << relative_seq(ack) << endl;
		cerr << "RangeManager::processAck: Error in ack processing. Exiting." << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	if (!ret)
		printf("ACK failed to find packet!\n");

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


/* TODO: Check handling of invalid ranges */
void RangeManager::genStats(struct byteStats *bs) {
	int latency;
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	vector<double> latencies;
	vector<double> payload_lengths;
	int tmp_byte_count = 0;
	bs->minLat = bs->minLength = (numeric_limits<int>::max)();

	for (; it != it_end; it++) {
		/* Skip if invalid (negative) latency or dummy range */
		tmp_byte_count = it->second->getNumBytes();
		payload_lengths.push_back(tmp_byte_count);
		bs->cumLength += tmp_byte_count;

		if (tmp_byte_count == 1) {
			printf("Payload is 1!\n");
			printf("Range (%lu, %lu, %lu) \n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getRDBSeq()), relative_seq(it->second->getEndSeq()));
		}

		if (tmp_byte_count) {
			if (tmp_byte_count > bs->maxLength)
				bs->maxLength = tmp_byte_count;
			if (tmp_byte_count < bs->minLength) {
				bs->minLength = tmp_byte_count;
			}
		}

		if ((latency = it->second->getSendAckTimeDiff())) {
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
				continue; /* Skip */
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
		double meanLen =  sumLen / conn->nrDataPacketsSent;

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
	int numDummy = 0;
	ulong tmpEndSeq = 0;

	multimap<ulong, Range*>::iterator first, it, it_end, prev;
	first = it = ranges.begin();
	it_end = ranges.end();
	prev = it_end;

	/* FirstRange.startSeq == firstSeq
	   LastRange.endSeq == lastSeq
	   every packet in between are aligned */
	if (it->second->getStartSeq() != 0) {
		printf("firstSeq: %lu, StartSeq: %lu\n", firstSeq, it->second->getStartSeq());
		printf("RangeManager::validateContent: firstSeq != StartSeq (%lu != %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(firstSeq));
		printf("First range (%lu, %lu, %lu)\n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getRDBSeq()), relative_seq(it->second->getEndSeq()));
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

				printf("Prev Range (%lu, %lu, %lu) Len: %u\n", relative_seq(prev->second->getStartSeq()), relative_seq(prev->second->getRDBSeq()),
				       relative_seq(prev->second->getEndSeq()), prev->second->getNumBytes());
				printf("Curr Range (%lu, %lu, %lu) Len: %u\n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getRDBSeq()),
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
		if (it->second->isDummy())
			numDummy++;

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
		nrDummy = numDummy;

	}
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "First seq: " << firstSeq << " Last seq: " <<  lastSeq << endl;
		cerr << "Number of ranges: " << ranges.size() << endl;
		cerr << "Number of dummy ranges: " << numDummy << endl;
		cerr << "Number of bytes: " << lastSeq - firstSeq << endl;
		cerr << "numSendTimes: " << numSendTimes << endl;
		cerr << "numAckTimes: " << numAckTimes << endl;
		cerr << "Is first range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Is last range acked?: " << ranges.begin()->second->isAcked() << endl;
		cerr << "Last range: startSeq: " << ranges.begin()->second->getStartSeq()
			 << " - endSeq: " << ranges.begin()->second->getEndSeq() << endl;
	}
}

/*
  This is used to track the data in regards to retrans or rdb. This functionality is somewhat a duplicate of the Range tracking in ranges.
  It's called both with sent end received data ranges.
 */
void RangeManager::insert_byte_range(ulong start_seq, ulong end_seq, bool sent, struct DataSeg *data_seg, int level) {
	int debug_print;
	ByteRange *last_br = NULL;
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt_end = brMap.end();
	brIt = brIt_end;
	char prefix[100];

	debug_print = GlobOpts::debugLevel == 6;
//	debug_print = 1;

	//indent_print("insert seq: %lu, rel: %lu\n", start_seq, relative_seq(start_seq));

	/*

	  // 1363862162
	if (relative_seq(start_seq) >= 2670586023 && relative_seq(start_seq) <= 2670587023) {
		debug_print = 1;
	}

	if (relative_seq(start_seq) >= 1363862162) {
		debug_print = 1;
	}

	if (relative_seq(start_seq) >= 1363862162 && relative_seq(start_seq) <= 1363868162) {
		debug_print = 1;
	}

	if (relative_seq(start_seq) >= 961473761 && relative_seq(start_seq) <= 961474861) {
		debug_print = 1;
	}

	*/


//	max_seq = 2670598023;

	bool this_is_rdb_data = data_seg->is_rdb && data_seg->rdb_end_seq > start_seq;

	if (relative_seq(start_seq) > max_seq) {
		printf("RETURN!\n");
		return;
	}

	int i;
	int indent = level * 3;
	for (i = 0; i < indent; i++) {
		prefix[i] = ' ';
	}
	sprintf(prefix + indent, "%d", level);

#define indent_print(format, args...) printf("%s "format, prefix, args)
#define indent_print2(format) printf("%s "format, prefix)

	if (debug_print) {
		if (!level)
			printf("\n");
		indent_print("insert_byte_range (%lu): (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq - start_seq +1,
		       relative_seq(start_seq), relative_seq(end_seq), sent, data_seg->retrans, data_seg->is_rdb);
	}

	// An ack
	if (start_seq == end_seq) {
		return;
	}

	if (brIt == brIt_end) {
		// Check if this range exists
		brIt = brMap.find(start_seq);
	}

	// Doesn't exist
	if (brIt == brIt_end) {
		if (!sent) {
			indent_print2("Received non-existent byte range!\n");
			warn_with_file_and_linenum(__FILE__, __LINE__);
		}

		if (debug_print) {
			indent_print("Adding: %lu - %lu\n", relative_seq(start_seq), relative_seq(end_seq));
		}

		// Ack / syn-ack / ack
		if ((start_seq - end_seq) == 0) {

			if (start_seq == firstSeq) {
				last_br = new ByteRange(start_seq, end_seq);
				last_br->sent_count += 1;
				last_br->retrans_count += data_seg->retrans;
				last_br->rdb_count += data_seg->is_rdb;
				last_br->tstamps_tcp.push_back(data_seg->tstamp_tcp);
				//last_br->tstamp_pcap = data_seg->tstamp_pcap;
				brMap.insert(pair<ulong, ByteRange*>(start_seq, last_br));
				return;
			}
			else if (start_seq +1 == firstSeq) {
				indent_print2("FOUND ACK CRAP\n");
			}
		}

		multimap<ulong, ByteRange*>::iterator lowIt, highIt;
		//indent_print("start_seq: %lu,  start_seq - 10000: %lu\n", start_seq, (start_seq - 10000));
		lowIt = brMap.lower_bound(start_seq +1);
		highIt = brMap.upper_bound(end_seq);

		ulong new_end_seq = end_seq;

		// Try to find existing range with startSeq > lowIt->second->startSeq and endSeq <= lowIt->second->endSeq
		for (; lowIt != highIt && lowIt != highIt; lowIt++) {
			if (debug_print) {
				indent_print("FOUND: sent: %d  %lu - %lu\n", sent, lowIt->second->startSeq, lowIt->second->endSeq);
			}

			lowIt->second->sent_count++;

			if (new_end_seq == end_seq)
				new_end_seq = lowIt->second->startSeq -1;
		}

		if (start_seq < lastSeq) {
//			debug_print = 1;

			if (debug_print) {
				indent_print2("New Range is not newest!\n");
			}
			ulong lower = std::min(0UL, start_seq - 10000);
			//indent_print("lower: %lu\n", lower);
			lowIt = brMap.lower_bound(lower);

			// Search for existing ranges for this data
			for (; lowIt != highIt && lowIt != highIt;) {
				//debug_print = 1;

				//if (debug_print) {
				//	indent_print("lowIt->second->startSeq (%lu) <= start_seq (%lu): %d\n", relative_seq(lowIt->second->startSeq), relative_seq(start_seq),
				//	       lowIt->second->startSeq <= start_seq);
				//	indent_print("lowIt->second->endSeq   (%lu) <= start_seq (%lu): %d\n", relative_seq(lowIt->second->endSeq), relative_seq(start_seq),
				//	       lowIt->second->endSeq >= start_seq);
				//}

				// Found existing range
				// The existing range is bigger than the data to be registered, so we split the existing range
				if (lowIt->second->startSeq <= start_seq && lowIt->second->endSeq >= start_seq) {
					// Found existing range with matching data for: 4294747345 - 4294748792!
					//                             Existing range : 4294745897 - 4294748792
					//                                          New 4294745897 - 4294747345, 4294747346 - 4294748792

					if (lowIt->second->startSeq == start_seq) {
						printf("New Data is at the beginning of existing range!!\n");
						printf("Existing Range: %lu - %lu\n", relative_seq(lowIt->second->startSeq), relative_seq(lowIt->second->endSeq));
						printf("New data Range: %lu - %lu\n", relative_seq(start_seq), relative_seq(end_seq));
					}
					assert(lowIt->second->startSeq != start_seq && "New Data is at beginning of existing range!!\n");

					// Splitting existing range
					//ByteRange *new_br = new ByteRange(lowIt->second->startSeq, start_seq -1);
					int end_matches = end_seq == lowIt->second->endSeq;
					ByteRange *cur_br = lowIt->second;

					if (debug_print) {
						indent_print("SENT: %d, rdb: %d, retrans: %d\n", sent, data_seg->is_rdb, data_seg->retrans);
						indent_print("\nFound existing range with matching data\n            for: %lu - %lu!\n", relative_seq(start_seq), relative_seq(end_seq));
						indent_print("Existing range : %lu - %lu\n", relative_seq(lowIt->second->startSeq), relative_seq(lowIt->second->endSeq));
						indent_print("Old Range      : %lu - %lu\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq));
					}

					// Split the current range in two. The new range will be at the beginning of the old (existing range)
					// The new data matches the existing data
					//assert(0 && "HMMMM");
					ByteRange *new_br = cur_br->split_start(cur_br->startSeq, start_seq -1);

					if (sent) {
						cur_br->sent_count++;
						cur_br->retrans_count += data_seg->retrans;
						cur_br->rdb_count += data_seg->is_rdb;
					}
					else {
						cur_br->increase_received(data_seg->tstamp_tcp);
						//assert(0 && "TEST\n");
						assert(cur_br->received_tstamp_tcp && "TEST\n");
						//new_br->split_after_sent = true;
					}

					//assert(sent && "Not sent but still sount_count is increased!!!\n");

					//printf("RETRANS: %d\n", data_seg->retrans);
					//printf("IS  RDB: %d\n", data_seg->is_rdb);

					cur_br->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);

					if (this_is_rdb_data) {
						cur_br->rdb_tstamps_tcp.push_back(data_seg->tstamp_tcp);
						assert(data_seg->retrans == 0 && "Should not be retrans!\n");
					}
					else
						cur_br->tstamps_tcp.push_back(data_seg->tstamp_tcp);

					if (debug_print) {
						indent_print("New Range      : %lu - %lu\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq));
						indent_print("Old Range      : %lu - %lu\n", relative_seq(cur_br->startSeq), relative_seq(cur_br->endSeq));
					}
					// Remove current Range
					brMap.erase(lowIt++);
					// Add existing and new range with correct key
					brMap.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
					brMap.insert(pair<ulong, ByteRange*>(cur_br->startSeq, cur_br));

					if (!end_matches) {
						//indent_print("End seqs do not match! %lu != %lu\n", relative_seq(end_seq), relative_seq(cur_br->endSeq));
						if (cur_br->endSeq > end_seq) {
							ByteRange *new_br = cur_br->split_end(end_seq + 1, cur_br->endSeq);
							brMap.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
							return;
						}
						else {
							assert(0 && "FACK!\n");
						}
					}
					else {
						//indent_print("Successfully added tricky range\n");
						return;
					}
				}
				else
					lowIt++;
			}
		}

		if (sent) {

			if (debug_print) {
				indent_print("data_seg->is_rdb: %d\n", data_seg->is_rdb  );
				indent_print("data_seg->rdb_end_seq > start_seq: %lu > %lu: %d\n", relative_seq(data_seg->rdb_end_seq), relative_seq(start_seq), data_seg->rdb_end_seq > start_seq);
			}

			// This Range has some RDB data and some new data, so make two Ranges
			if (this_is_rdb_data) {
				indent_print("this_is_rdb_data: %d\n", this_is_rdb_data);

				ByteRange *new_br = new ByteRange(start_seq, data_seg->rdb_end_seq);
				last_br = new ByteRange(data_seg->rdb_end_seq +1, new_end_seq);
				last_br->sent_count = new_br->sent_count = 1;
				last_br->sent_tstamp_pcap = new_br->sent_tstamp_pcap = data_seg->tstamp_pcap;
				last_br->rdb_tstamps_tcp.push_back(data_seg->tstamp_tcp);
				last_br->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);
				assert(data_seg->retrans && "Shouldn' be retrans?\n");

				//last_br->retrans += data_seg->retrans; // Shouldn't happen?
				brMap.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
				brMap.insert(pair<ulong, ByteRange*>(last_br->startSeq, last_br));

				indent_print("New RDB ByteRange (%lu) (%lu - %lu)\n", new_br->endSeq - new_br->startSeq + 1, relative_seq(new_br->startSeq), relative_seq(new_br->endSeq));
				indent_print("New     ByteRange (%lu) (%lu - %lu)\n", last_br->endSeq - last_br->startSeq + 1, relative_seq(last_br->startSeq), relative_seq(last_br->endSeq));
				assert(0 && "EXIT\n");
			}
			else {
				if (debug_print) {
					indent_print2("YES!!!!!\n");
					indent_print("New ByteRange (%lu) (%lu - %lu)\n", new_end_seq - start_seq + 1, relative_seq(start_seq), relative_seq(new_end_seq));
					indent_print("RDB end seq: %lu\n", relative_seq(data_seg->rdb_end_seq));
				}
				last_br = new ByteRange(start_seq, new_end_seq);
				last_br->sent_count = 1;

				if (debug_print) {
					indent_print("this_is_rdb_data: %d\n", this_is_rdb_data);
					indent_print("data_seg->is_rdb: %d\n", data_seg->is_rdb);
				}

				if (debug_print) {
					indent_print("Adding tcp timestamp 5 to reg : %u\n", data_seg->tstamp_tcp);
					if (data_seg->tstamp_tcp == 1968771524)
						colored_printf(RED, "TSTAMP: %u\n", data_seg->tstamp_tcp);
				}
				last_br->tstamps_tcp.push_back(data_seg->tstamp_tcp);
				last_br->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);

				//last_br->retrans += data_seg->retrans;

				assert(data_seg->retrans == 0 && "Shouldn't be retrans!\n");
				//assert(data_seg->is_rdb == 0 && "Shouldn't be RDB?!\n");
				//printf("this_is_rdb_data: %d\n", this_is_rdb_data);

				assert(this_is_rdb_data == 0 && "Shouldn't be RDB?!\n");

				if ((new_end_seq - start_seq) > 100) {
					if (debug_print) {
						indent_print("Inserting new big range: %lu\n", (new_end_seq - start_seq +1));
					}
					//exit(0);
				}

				//last_br->is_rdb += data_seg->is_rdb;
				last_br->sent_tstamp_pcap = data_seg->tstamp_pcap;
				brMap.insert(pair<ulong, ByteRange*>(start_seq, last_br));
			}
		}
		else {
			assert(sent && "RECEIVED??\n");
		}
		if (debug_print) {
			//indent_print("Exiting debug print!\n");
			//exit(0);
		}
	}
	// Exists in map
	else {
		if (debug_print) {
			indent_print("FOUND START: sent:%d, %lu - %lu (%lu)\n", sent, relative_seq(start_seq), relative_seq(end_seq), end_seq - start_seq + 1);
			indent_print("Current startseq: %lu, endseq: %lu, new endseq: %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), relative_seq(end_seq));
		}

		// No payload, so it's an ack/syn/syn/ack-whatever
		if ((start_seq - end_seq) == 0) {
			brIt = brMap.find(start_seq -1);
			if (brIt != brIt_end) {
				indent_print("brIt->second->received_count: %d\n", brIt->second->received_count);
				brIt->second->received_count += 1;
				indent_print("Increase received count of %lu\n", brIt->second->startSeq);
			}
			return;
		}

		// The end_seq of the new range doesn't correspond to the end-seq of the entry in the map
		if (brIt->second->endSeq != end_seq) {

			if (!sent) {
				// The ack on the syn-ack
				if (end_seq == firstSeq +1) {
					brIt = brMap.find(start_seq -1);
					brIt->second->received_count++;
					return;
				}
				else {
					//indent_print("insert_byte_range (%lu): (%lu - %lu), sent: %d, retrans: %d, is_rdb: %d\n", end_seq - start_seq +1,
					//			 relative_seq(start_seq), relative_seq(end_seq), sent, data_seg->retrans, data_seg->is_rdb);
					//assert(0 && "Should come here??\n");
				}
			}

			// Reaches multiple byte ranges
			if (brIt->second->endSeq < end_seq) {
				if (debug_print) {
					indent_print("Overlaps multiple byte ranges: %lu - %lu\n", relative_seq(start_seq), relative_seq(end_seq));
					indent_print("Increase count of %lu - %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq));
					indent_print("Setting is_rdb : %d\n", data_seg->is_rdb);
					indent_print("Setting retrans: %d\n", data_seg->retrans);
				}

				if (sent) {
					brIt->second->sent_count++;
					if (this_is_rdb_data) {
						brIt->second->rdb_tstamps_tcp.push_back(data_seg->tstamp_tcp);
						//printf("data_seg->retrans: %d\n", data_seg->retrans);
						if (debug_print) {
							indent_print("Adding tcp timestamp 1 to rdb : %u\n", data_seg->tstamp_tcp);
							if (data_seg->tstamp_tcp == 1968771524)
								colored_printf(RED, "TSTAMP: %u\n", data_seg->tstamp_tcp);
						}
						assert(data_seg->retrans == 0 && "Should not be retrans!\n");
					}
					else {
						brIt->second->tstamps_tcp.push_back(data_seg->tstamp_tcp);
						if (debug_print) {
							indent_print("Adding tcp timestamp 2 to reg : %u\n", data_seg->tstamp_tcp);
							if (data_seg->tstamp_tcp == 1968771524)
								colored_printf(RED, "TSTAMP: %u\n", data_seg->tstamp_tcp);
						}
					}
					brIt->second->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);
				}
				else {
					brIt->second->increase_received(data_seg->tstamp_tcp);
					assert(brIt->second->received_tstamp_tcp && "TEST\n");
				}
				if (!sent) {
					//colored_printf(data_seg->retrans ? RED : NO_COLOR, "REGISTER!!\n");
					//indent_print2("Register received\n");
					//indent_print("retrans %d -> %d\n", brIt->second->retrans, brIt->second->retrans + data_seg->retrans);
					//indent_print("is_rdb  %d -> %d\n", brIt->second->is_rdb, brIt->second->is_rdb + data_seg->is_rdb);
					//exit(0);
				}
				brIt->second->retrans_count += data_seg->retrans;
				brIt->second->rdb_count += data_seg->is_rdb;

				// Recursive call to insert the remaining data
				insert_byte_range(brIt->second->endSeq +1, end_seq, sent, data_seg, level +1);
			}
			// Reaches less than the range, split current range
			else {
				ByteRange *new_br = brIt->second->split_end(end_seq +1, brIt->second->endSeq);
				if (debug_print) {
					indent_print2("Reaches less, split existing Range\n");
					indent_print("Existing range : %lu - %lu -> %lu - %lu\n", relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq),
					       relative_seq(brIt->second->startSeq), relative_seq(end_seq));
					indent_print("New range      : %lu - %lu\n", relative_seq(new_br->startSeq), relative_seq(new_br->endSeq));
				}

				if (sent) {
					brIt->second->sent_count++;
					brIt->second->retrans_count += data_seg->retrans;
					brIt->second->rdb_count += data_seg->is_rdb;

					if (this_is_rdb_data) {
						brIt->second->rdb_tstamps_tcp.push_back(data_seg->tstamp_tcp);
						assert(data_seg->retrans != 0 && "Should not be retrans!\n");
					}
					else {
						brIt->second->tstamps_tcp.push_back(data_seg->tstamp_tcp);
					}
					brIt->second->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);
				}
				else {
					//assert(0 && "RECEIVED! exit\n");
					new_br->split_after_sent = true;
					brIt->second->split_after_sent = true;
					brIt->second->increase_received(data_seg->tstamp_tcp);
					assert(brIt->second->received_tstamp_tcp && "TEST\n");
				}
				brMap.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
			}
		}
		else {
			// The end_seq of the new range correspond to the end-seq of the entry in the map, so it's a duplicate
			if (debug_print) {
				indent_print("ALREADY EXISTS: sent: %d, %lu - %lu - increasing count\n", sent, relative_seq(start_seq), relative_seq(end_seq));
			}
			if (sent) {
				brIt->second->sent_count++;
				brIt->second->retrans_count += data_seg->retrans;
				brIt->second->rdb_count += data_seg->is_rdb;

				if (this_is_rdb_data) {
					brIt->second->rdb_tstamps_tcp.push_back(data_seg->tstamp_tcp);
					assert(data_seg->retrans == 0 && "Should not be retrans!\n");

					if (debug_print) {
						indent_print("Adding tcp timestamp 3 to rdb : %u\n", data_seg->tstamp_tcp);
					}
				}
				else {
					brIt->second->tstamps_tcp.push_back(data_seg->tstamp_tcp);
					if (debug_print) {
						indent_print("Adding tcp timestamp 4 to reg : %u\n", data_seg->tstamp_tcp);
					}
				}
				brIt->second->lost_tstamps_tcp.push_back(data_seg->tstamp_tcp);
			}
			else {
				brIt->second->increase_received(data_seg->tstamp_tcp);
				if (debug_print) {
					printf("Setting received timestamp: %u\n", brIt->second->received_tstamp_tcp);
					printf("tstamps: %lu, rdb-stamps: %lu", brIt->second->tstamps_tcp.size(), brIt->second->rdb_tstamps_tcp.size());
				}
				assert(brIt->second->received_tstamp_tcp && "TEST\n");
			}
		}
	}
}

void RangeManager::write_loss_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *out_stream) {
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt = brMap.begin();
	brIt_end = brMap.end();

	timeval next, t_slice, next_tmp;
	t_slice.tv_sec = slice_interval;
	t_slice.tv_usec = 0;

	if (brIt != brIt_end)
		timeradd(&(brIt->second->sent_tstamp_pcap), &t_slice, &next);

	int retrans_count = 0;

	for (; brIt != brIt_end; brIt++) {

		if (timercmp(&(brIt->second->sent_tstamp_pcap), &next, <)) {
			fprintf(out_stream, "%10d", retrans_count);
			retrans_count = 0;
			memcpy(&next_tmp, &next, sizeof(struct timeval));
			timeradd(&next_tmp, &t_slice, &next);
		}
		retrans_count += brIt->second->retrans_count;
	}
	fprintf(out_stream, "\n");
}

void RangeManager::write_retrans_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *out_stream) {
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt = brMap.begin();
	brIt_end = brMap.end();
/*
	timeval next, t_slice, next_tmp;
	t_slice.tv_sec = slice_interval;
	t_slice.tv_usec = 0;

	if (brIt != brIt_end)
		timeradd(&(brIt->second->sent_tstamp_pcap), &t_slice, &next);

	int retrans_count = 0;

	for (; brIt != brIt_end; brIt++) {

		if (timercmp(&(brIt->second->sent_tstamp_pcap), &next, <)) {
			fprintf(out_stream, "%10d", retrans_count);
			retrans_count = 0;
			memcpy(&next_tmp, &next, sizeof(struct timeval));
			timeradd(&next_tmp, &t_slice, &next);
		}
		retrans_count += brIt->second->retrans;
	}
	fprintf(out_stream, "\n");

	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	int num_retr_tmp;
	int diff_tmp;
	for (; it != it_end; it++) {
		diff_tmp = it->second->getSendAckTimeDiff();
		if (diff_tmp > 0) {
			num_retr_tmp = it->second->getNumRetrans();
			// all
			GlobStats::retrans_vectors[0]->push_back(diff_tmp);
			// Retrans vector for that number of retransmissions
			if (num_retr_tmp <= GlobOpts::max_retrans_stats)
				GlobStats::retrans_vectors[num_retr_tmp]->push_back(diff_tmp);

			// Write to file
			if (!(GlobOpts::aggOnly)) {
				*streams[0] << it->second->getSendAckTimeDiff() << endl;
				if (num_retr_tmp <= GlobOpts::max_retrans_stats)
					*streams[num_retr_tmp] << it->second->getSendAckTimeDiff() << endl;
			}
		}
	}

	for (unsigned long int i = 0; i < streams.size(); i++) {
		streams[i]->close();
		delete streams[i];
	}
*/
}

void RangeManager::calculateRDBStats() {
	ByteRange *prev = NULL;
	int index = 0;
	int lost_tmp = 0;
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	rdb_stats_available = true;

	if (GlobOpts::print_packets) {
		cout << endl << "Packet details for conn: " << conn->getConnKey() << endl;
	}
	int match_fails = 0;
	int lost_packets = 0;
	bool prev_pack_lost = false;

	bool has_recv_data = hasReceiveData();

	brIt = brMap.begin();
	brIt_end = brMap.end();
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
			match_fails++;
		}

		int rdb_miss;
		int rdb_hit = 0;
		int rdb_count = brIt->second->rdb_count;
		if (rdb_count && brIt->second->recv_type == RDB) {
			rdb_count -= 1; // Remove the successful rdb transfer
			rdb_hit += brIt->second->byte_count;
			rdb_byte_hits += brIt->second->byte_count;
		}

		if (brIt->second->recv_type == RDB) {
			rdb_packet_hits++;
		}

		rdb_miss = rdb_count * brIt->second->byte_count;
		rdb_byte_miss += rdb_miss;

		if (GlobOpts::print_packets) {
			string type;
			switch (brIt->second->recv_type) {
			case DATA: type = "DTA"; break;
			case RDB: type = "RDB"; break;
			case RETR: type = "RTR"; break;
			case DEF: type = "DEF"; break;
			default: printf("INVALID TYPE!\n");
			}

			printf("Byte range (%4lu): %lu - %lu: sent: %d, received: %d, retrans_count: %d, rdb_count: %d, RCV: %s, rdb-miss: %-3d rdb-hit: %-3d",
				   brIt->second->endSeq - brIt->second->startSeq +1,
			       relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), brIt->second->sent_count, brIt->second->received_count,
			       brIt->second->retrans_count, brIt->second->rdb_count, type.c_str(), rdb_miss, rdb_hit);
			printf(" ACKtime: %d", brIt->second->getSendAckTimeDiff());
		}

		if (brIt->second->sent_count != brIt->second->received_count) {
			if (GlobOpts::print_packets) {
				printf("   LOST %d, index: %d", brIt->second->sent_count - brIt->second->received_count, index);
			}
			lost_range_count += (brIt->second->sent_count - brIt->second->received_count);
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
			if (!brIt->second->retrans_count && !brIt->second->rdb_count && (rdb_miss || rdb_hit)) {
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
			printf("\n");
		}
	}
	if (match_fails)
		printf("Failed to find timestamp for %d out of %ld packets.\n", match_fails, brMap.size());

	printf("Lost packets: %d\n", lost_packets);
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

	/* Store ranges with no corresponding packet
	   on the receiver side, and delete them after
	   traversing all ranges */
	vector<multimap<ulong, Range*>::iterator> delList;

	/* Create map with references to the ranges */
	rit = recvd.begin();
	rit_end = recvd.end();
	multimap<ulong, struct DataSeg*> rsMap;

	for (; rit != rit_end ; rit++) {
		struct DataSeg *tmpRd = *rit;
		rsMap.insert(pair<ulong, struct DataSeg*>(tmpRd->seq, tmpRd));
	}

	std::pair <std::multimap<ulong, struct DataSeg*>::iterator, std::multimap<ulong, struct DataSeg*>::iterator> ret;

	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	int packet_match_limit = 10; // How many packets after the last match after we break
	int ranges_not_received = 0;
	int packet_index = -1;
	for (; it != it_end; it++) {
		int matched = -1;
		ulong sndStartSeq = it->second->getStartSeq();
		ulong sndRDBSeq = it->second->getRDBSeq();
		ulong sndEndSeq = it->second->getEndSeq();

		packet_index++;
/*
		printf("Range (%4lu): %lu - %lu: retrans_count: %d, rdb_count: %d",
			   it->second->getEndSeq() - it->second->getStartSeq() +1,
			   relative_seq(it->second->getStartSeq()), relative_seq(it->second->getEndSeq()),
			   it->second->getNumRetrans(), it->second->getNumBundled());
		printf(" ACKtime: %d\n", it->second->getSendAckTimeDiff());
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

		if (absLow > absHigh) {
			cerr << "Wrapped TCP sequence number detected. Tagging range for deletion" << endl;
			delList.push_back(it);
			continue;
		}

		lowIt = rsMap.lower_bound(absLow);
		highIt = rsMap.upper_bound(absHigh);

		struct timeval match;
		memset(&match, 9, sizeof(match));

		if (GlobOpts::debugLevel == 7) {
			printf("\n\nSent        seq: (%10lu - %10lu - %10lu) Len: %u\n", relative_seq(sndStartSeq), relative_seq(sndRDBSeq), relative_seq(sndEndSeq), it->second->getNumBytes());
		}

		int no_more_matches = 0;
		int test = 0;

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

				if (no_more_matches) {
					printf("Encountered matching packet after the current limit (%d)!!!\n", packet_match_limit);
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

					if (test) {
						printf("               Found exact match (%lu, %lu)\n", tmpRd->seq, tmpRd->endSeq);
					}

					if (GlobOpts::debugLevel == 7) {
						printf("               Found exact match");
					}
					it->second->setExactMatchedAcked();
					break;
				}
				else if (tmpRd->seq >= sndStartSeq && tmpRd->endSeq <= sndEndSeq) {
					break;
					if (test)
						printf("               NONE\n");
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
				ranges_not_received++;
				if (GlobOpts::debugLevel == 8) {
					fprintf(stderr, "Packet not found on receiver (%lu - %lu - %lu) Len: %u\n",
						relative_seq(it->second->getStartSeq()), relative_seq(it->second->getRDBSeq()),
						relative_seq(it->second->getEndSeq()),  it->second->getNumBytes());
				}
				delList.push_back(it);
				continue;
			}
		}

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
	ulong wrap_index;
	wrap_index = (conn->firstSeq + seq) / 4294967296L;
	if (GlobOpts::relative_seq)
		return seq;
	ulong res = seq + firstSeq;
	res -= ((ulong) wrap_index * 4294967296L);
	return res;
}

Range* RangeManager::getHighestAcked() {
	multimap<ulong, Range*>::iterator it, it_end;
	it_end = ranges.end();
	if (highestAckedIt == it_end)
		return NULL;
	return highestAckedIt->second;
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
		multimap<ulong, Range*>::iterator startIt;
		multimap<ulong, Range*>::reverse_iterator endIt;
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

/* Returns the difference between the start
   of the dump and r in seconds */
int RangeManager::getTimeInterval(Range *r){
	struct timeval start, current, tv;
	int time;
	start = *(ranges.begin()->second->getSendTime());
	current = *(r->getSendTime());
	timersub(&current, &start, &tv);
	time = tv.tv_sec + (tv.tv_usec / 1000000);
	return time;
}

void RangeManager::makeCdf() {
	long diff;
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for (; it != it_end; it++) {
		diff = it->second->getRecvDiff();
		diff -= lowestDiff;

		if (cdf.count(diff) > 0) {
			/*  Add bytes to bucket */
			map<const int, int>::iterator element = cdf.find(diff);
			element->second = element->second + it->second->getNumBytes();
		} else {
			/* Initiate new bucket */
			cdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
		}
		if (GlobOpts::aggregate) {
			if ( GlobStats::cdf.count(diff) > 0 ){
				/*  Add bytes to bucket */
				map<const int, int>::iterator element = GlobStats::cdf.find(diff);
				element->second = element->second + it->second->getNumBytes();
			} else {
				/* Initiate new bucket */
				GlobStats::cdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
			}
		}
	}
}

void RangeManager::registerDcDiffs() {
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for (; it != it_end; it++) {
		long diff = it->second->getRecvDiff();
		/* Compensate for drift */
		diff -= (int)(drift * getTimeInterval(it->second));

		it->second->setDcDiff(diff);

		if( diff < lowestDcDiff )
			lowestDcDiff = diff;

		if(GlobOpts::debugLevel==4 || GlobOpts::debugLevel==5){
			cerr << "dcDiff: " << diff << endl;
		}
	}
}

void RangeManager::makeDcCdf(){
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	for(; it != it_end; it++){
		long diff = it->second->getDcDiff() - lowestDcDiff;
		if ( dcCdf.count(diff) > 0 ){
			/*  Add bytes to bucket */
			map<const int, int>::iterator element = dcCdf.find(diff);
			element->second = element->second + it->second->getNumBytes();
		}else{
			/* Initiate new bucket */
			dcCdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
		}
		if(GlobOpts::aggregate){
			if ( GlobStats::dcCdf.count(diff) > 0 ){
				/*  Add bytes to bucket */
				map<const int, int>::iterator element = GlobStats::dcCdf.find(diff);
				element->second = element->second + it->second->getNumBytes();
			}else{
				/* Initiate new bucket */
				GlobStats::dcCdf.insert(pair<int, int>(diff, it->second->getNumBytes()));
			}
		}

		if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
			it->second->printValues();
		}
	}
	GlobStats::totNumBytes += getTotNumBytes();

	if ( drift != -1) {
		if (GlobStats::avgDrift == 0)
			GlobStats::avgDrift = drift;
		else
			GlobStats::avgDrift = (GlobStats::avgDrift + drift) / 2;
	}
}

void RangeManager::printCDF(ofstream *stream) {
	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	char print_buf[300];
	nit = cdf.begin();
	nit_end = cdf.end();

	if (GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5) {
		*stream << "lowestDiff: " << lowestDiff << endl;
	}

	*stream << "#Relative delay      Percentage" << endl;
	for (; nit != nit_end; nit++) {
		cdfSum += (double) (*nit).second / getTotNumBytes();
		sprintf(print_buf, "time: %10d    CDF: %.10f\n", (*nit).first, cdfSum);
		*stream << print_buf << endl;
	}
}

void RangeManager::printDcCdf(ofstream *stream) {
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
		cdfSum += (double)(*nit).second / getTotNumBytes();
		sprintf(print_buf, "time: %10d    CDF: %.10f\n", (*nit).first, cdfSum);
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
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	printf("\nranges : %lu\n", ranges.size());
	printf("branges: %lu\n", brMap.size());

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
		diff_tmp = it->second->getSendAckTimeDiff();
		if (diff_tmp > 0) {
			num_retr_tmp = it->second->getNumRetrans();
			// all
			GlobStats::retrans_vectors[0]->push_back(diff_tmp);
			// Retrans vector for that number of retransmissions
			if (num_retr_tmp <= GlobOpts::max_retrans_stats)
				GlobStats::retrans_vectors[num_retr_tmp]->push_back(diff_tmp);

			// Write to file
			if (!(GlobOpts::aggOnly)) {
				*streams[0] << it->second->getSendAckTimeDiff() << endl;
				if (num_retr_tmp <= GlobOpts::max_retrans_stats)
					*streams[num_retr_tmp] << it->second->getSendAckTimeDiff() << endl;
			}
		}
	}

	for (unsigned long int i = 0; i < streams.size(); i++) {
		streams[i]->close();
		delete streams[i];
	}
}
