#include "RangeManager.h"

map<const int, int> GlobStats::cdf;
map<const int, int> GlobStats::dcCdf;
float GlobStats::avgDrift = 0;
vector<int> GlobStats::retr1;
vector<int> GlobStats::retr2;
vector<int> GlobStats::retr3;
vector<int> GlobStats::retr4;
vector<int> GlobStats::retr5;
vector<int> GlobStats::retr6;
vector<int> GlobStats::all;

RangeManager::~RangeManager() {
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();
	for (; it != it_end; it++) {
		delete it->second;
	}
	vector<recvData*>::iterator rit, rit_end;
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
Range* RangeManager::insertSentRange(struct sendData *sd) {
	uint32_t startSeq = sd->seq;
	uint32_t endSeq = sd->endSeq;
	timeval *tv = &(sd->time);
	Range* range = NULL;

	if (GlobOpts::debugLevel == 6) {
		printf("\ninsertSentRange - retrans: %d, is_rdb %d\n", sd->retrans, sd->is_rdb);
	}

	// Ignore acks (including SYN/ack and FIN/ack)
	if ((GlobOpts::print_packets || GlobOpts::rdbDetails) && startSeq != endSeq)
		insert_byte_range(startSeq, endSeq, true, sd->retrans, sd->is_rdb, 0);

	int ranges_size = ranges.size();
	if (ranges_size <= 1 && sd->payloadSize == 0) { /* First or second packet in stream */
		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
			cerr << "-------Creating first range---------" << endl;

		if (ranges_size == 0) {
			range = new Range(startSeq, startSeq, endSeq, sd->payloadSize, sd->data, tv, false, this);
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
		range = new Range(startSeq, startSeq, endSeq, sd->payloadSize, sd->data, tv, false, this);
		ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));
		lastSeq = startSeq + sd->payloadSize;

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
		if (sd->payloadSize != 0) {
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
		if (sd->payloadSize == 0) {
			range = new Range(startSeq, startSeq, endSeq, sd->payloadSize, sd->data, tv, false, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));
			lastSeq = startSeq + sd->payloadSize;
		}
		else {

			/* Insert dummy range */
			if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5){
				cerr << "-------Missing packet(s): inserting dummy range---------" << endl;
				cerr << "Dummy range: lastSeq:  " << relative_seq(lastSeq) << " - startSeq: " << relative_seq(startSeq)
				     << " - size: " << relative_seq(startSeq +1 - lastSeq) << endl;
				cerr << "Valid range: startSeq: " << relative_seq(startSeq) << " - endSeq:   " << relative_seq(endSeq)
				     << " - size: " << relative_seq(endSeq +1 - startSeq ) << endl;
			}

			range = new Range(lastSeq, lastSeq, startSeq -1, startSeq - lastSeq, NULL, tv, true, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));

			/* Then insert the new, valid range */
			range = new Range(startSeq, startSeq, endSeq, sd->payloadSize, sd->data, tv, false, this);
			ranges.insert(pair<uint32_t, Range*>(range->getStartSeq(), range));

			lastSeq = startSeq + sd->payloadSize;
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->payloadSize);
			}
		}
	}

	else if (startSeq < lastSeq) { /* We have some kind of overlap */

		if (endSeq <= lastSeq) {/* All bytes are already registered: Retransmission */

			if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
				cerr << "-------All bytes have already been registered - discarding---------" << endl;
			/* Traverse all affected ranges and tag all
			   ranges that contain retransmitted bytes */
			multimap<ulong, Range*>::reverse_iterator it, it_end;
			it_end = ranges.rend();
			int count = 0;
			for (it = ranges.rbegin(); it != it_end; it++) {
				if (startSeq > it->second->getEndSeq())
					break;

				if ((endSeq + 1) > it->second->getStartSeq()) {
					count++;
					it->second->incNumRetrans(); // Count a new retransmssion
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

			if ((endSeq - startSeq +1) != sd->payloadSize) {
				printf("Data len incorrect!\n");
				exit_with_file_and_linenum(1, __FILE__, __LINE__);
			}

			range = new Range(lastSeq, lastSeq, endSeq, sd->payloadSize, sd->data, tv, false, this);

			ranges.insert(pair<ulong, Range*>(range->getStartSeq(), range));
			lastSeq = startSeq + sd->payloadSize;
			if (lastSeq != (endSeq + 1)) {
				printf("INCORRECT: %u\n", sd->payloadSize);
			}

			/* Traverse all affected ranges and tag all
			   ranges that contain bundled bytes */
			multimap<ulong, Range*>::reverse_iterator it, it_end;
			it_end = ranges.rend();
			for (it = ranges.rbegin(); it != it_end; it++) {
				if (startSeq >= it->second->getEndSeq())
					break;
				if (endSeq > it->second->getStartSeq())
					it->second->incNumBundled(); /* Count a new bundling */
			}
		}
	}

	if ((startSeq + sd->payloadSize) > largestEndSeq) {
		largestEndSeq = startSeq + sd->payloadSize;
	}
	return range;
}

/* Register all bytes with a coomon send time as a range */
void RangeManager::insertRecvRange(struct sendData *sd) {
	struct recvData *tmpRecv = new struct recvData();
	tmpRecv->startSeq = sd->seq;
	tmpRecv->endSeq = sd->endSeq;
	tmpRecv->tv = (sd->time);
	tmpRecv->data = sd->data;
	tmpRecv->payload_len = sd->payloadSize;

	if (sd->payloadSize > 0)
		tmpRecv->endSeq -= 1;

	if(GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5 ){
		cerr << "Inserting receive data: startSeq=" << relative_seq(tmpRecv->startSeq) << ", endSeq=" << relative_seq(tmpRecv->endSeq) << endl;
		if (tmpRecv->startSeq == 0  || tmpRecv->endSeq == 0){
			cerr << "Erroneous seq." << endl;
		}
	}
	/* Insert all packets into data structure */
	recvd.push_back(tmpRecv);

	std::ostringstream key;
	key << tmpRecv->startSeq << ":" << tmpRecv->endSeq;
	return;
}

long get_timeval(timeval* tv) {
	long ms = 0;
	if (tv->tv_sec > 0) {
		ms += tv->tv_sec * 1000;
	}
	ms += (tv->tv_usec / 1000);
	return ms;
}

/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
bool RangeManager::processAck(ulong ack, timeval* tv) {
	Range* tmpRange;
	bool ret = false;

	multimap<ulong, Range*>::iterator it, it_end;
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

double median(vector<double>::const_iterator begin,
              vector<double>::const_iterator end) {
    int len = end - begin;
    vector<double>::const_iterator it = begin + len / 2;
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
	bs->minLength = 5000000;

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

		if ((latency = it->second->getDiff())) {
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

		if (retrans > 0) {
			if (retrans == 1) {
				bs->retrans[0]++;
			}
			if (retrans == 2) {
				bs->retrans[0]++;
				bs->retrans[1]++;
			}
			if (retrans >= 3) {
				bs->retrans[0]++;
				bs->retrans[1]++;
				bs->retrans[2]++;
			}
		}
		if (retrans > bs->maxRetrans)
			bs->maxRetrans = retrans;
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
		warn_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (!(ranges.rbegin()->second->getEndSeq() <= lastSeq && ranges.rbegin()->second->getEndSeq() >= (lastSeq - 1))) {
		printf("RangeManager::validateContent: lastSeq unaligned! lastSeq: %lu, EndSeq: %lu\n", relative_seq(lastSeq), relative_seq(ranges.rbegin()->second->getEndSeq()));
		warn_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (conn->totBytesSent != (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent)) {
		printf("conn->totBytesSent(%u) does not equal (totNewDataSent + totRDBBytesSent + totRetransBytesSent) (%u)\n", conn->totBytesSent, (conn->totNewDataSent + conn->totRDBBytesSent + conn->totRetransBytesSent));
		warn_with_file_and_linenum(1, __FILE__, __LINE__);
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

				printf("Prev Range (%lu, %lu, %lu) Len: %u\n", relative_seq(prev->second->getStartSeq()), relative_seq(prev->second->getRDBSeq()), relative_seq(prev->second->getEndSeq()), prev->second->getNumBytes());
				printf("Curr Range (%lu, %lu, %lu) Len: %u\n", relative_seq(it->second->getStartSeq()), relative_seq(it->second->getRDBSeq()), relative_seq(it->second->getEndSeq()), it->second->getNumBytes());
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
 */
void RangeManager::insert_byte_range(ulong start_seq, ulong end_seq, int sent, bool retrans, bool is_rdb, int level) {
	static int debug_print;
	ByteRange *last_br;
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt_end = brMap.end();
	brIt = brIt_end;

	debug_print = GlobOpts::debugLevel == 6;

	if (debug_print) {
		if (!level)
			printf("\n");
		printf("%d insert_byte_range: (%lu - %lu), retrans: %d, is_rdb: %d\n", level, start_seq, end_seq, retrans, is_rdb);
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
		if (debug_print) {
			printf("%d Adding: %lu - %lu\n", level, start_seq, end_seq);
		}

		// Ack / syn-ack / ack
		if ((start_seq - end_seq) == 0) {

			if (start_seq == firstSeq) {
				last_br = new ByteRange(start_seq, end_seq);
				last_br->sent_count += 1;
				last_br->retrans += retrans;
				last_br->is_rdb += is_rdb;
				brMap.insert(pair<ulong, ByteRange*>(start_seq, last_br));
				return;
			}
			else if (start_seq +1 == firstSeq) {
				printf("FOUND ACK CRAP\n");
			}
		}

		multimap<ulong, ByteRange*>::iterator lowIt, highIt;
		lowIt = brMap.lower_bound(start_seq + 1);
		highIt = brMap.upper_bound(end_seq);

		ulong new_end_seq = end_seq;

		// Try to find existing range with startSeq > lowIt->second->startSeq and endSeq <= lowIt->second->endSeq
		for (; lowIt != highIt && lowIt != brIt_end; lowIt++) {
			if (debug_print) {
				printf("FOUND: sent: %d  %lu - %lu\n", sent, lowIt->second->startSeq, lowIt->second->endSeq);
			}
			lowIt->second->sent_count++;

			if (new_end_seq == end_seq)
				new_end_seq = lowIt->second->startSeq -1;

		}

		if (sent) {
			last_br = new ByteRange(start_seq, new_end_seq);
			last_br->sent_count = 1;
			last_br->retrans += retrans;
			last_br->is_rdb += is_rdb;
			brMap.insert(pair<ulong, ByteRange*>(start_seq, last_br));
		}
		else {
		}
	}
	// Exists in map
	else {
		if (debug_print) {
			printf("FOUND START: sent:%d, %lu - %lu (%lu)\n", sent, start_seq, end_seq, end_seq - start_seq + 1);
			printf("Current startseq: %lu, endseq: %lu, new endseq: %lu\n", brIt->second->startSeq, brIt->second->endSeq, end_seq);
		}

		// No payload, so it's an ack/syn/syn/ack-whatever
		if ((start_seq - end_seq) == 0) {
			brIt = brMap.find(start_seq -1);
			if (brIt != brIt_end) {
				printf("brIt->second->received_count: %d\n", brIt->second->received_count);
				brIt->second->received_count += 1;
				printf("Increase received count of %lu\n", brIt->second->startSeq);
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
			}

			// Reaches multiple byte ranges
			if (brIt->second->endSeq < end_seq) {
				if (debug_print) {
					printf("Overlaps multiple byte ranges: %lu - %lu\n", start_seq, end_seq);
					printf("Increase count of %lu - %lu\n", brIt->second->startSeq, brIt->second->endSeq);
					printf("Adding %lu - %lu\n", brIt->second->endSeq +1, end_seq);
					printf("Setting is_rdb : %d\n", is_rdb);
					printf("Setting retrans: %d\n", retrans);
				}

				if (sent)
					brIt->second->sent_count++;
				else
					brIt->second->received_count++;

				brIt->second->retrans += retrans;
				brIt->second->is_rdb += is_rdb;

				insert_byte_range(brIt->second->endSeq +1, end_seq, sent, retrans, is_rdb, level +1);
			}
			// Reaches less than the range, split current range
			else {
				ByteRange *new_br = new ByteRange(end_seq +1, brIt->second->endSeq);
				new_br->sent_count = brIt->second->sent_count;
				brIt->second->endSeq = end_seq;
				if (sent) {
					brIt->second->sent_count++;
					brIt->second->retrans += retrans;
					brIt->second->is_rdb += is_rdb;
				}
				else {
					brIt->second->received_count++;
					brIt->second->split_after_sent = true;
				}
				brMap.insert(pair<ulong, ByteRange*>(new_br->startSeq, new_br));
			}
		}
		else {
			// The end_seq of the new range correspond to the end-seq of the entry in the map, so it's a duplicate
			if (debug_print) {
				printf("ALREADY EXISTS: sent: %d, %lu - %lu - increasing count\n", sent, start_seq, end_seq);
			}
			if (sent) {
				brIt->second->sent_count++;
				brIt->second->retrans += retrans;
				brIt->second->is_rdb += is_rdb;
			}
			else {
				brIt->second->received_count++;
			}
		}
	}
}

void RangeManager::calculateRDBStats() {
	ByteRange *prev = NULL;
	int index = 0;
	int lost_tmp = 0;
	int lost_range_count = 0;
	int sent_count = 0;
	int recv_count = 0;
	int bytes_lost = 0;
	int rdb = 0;
	multimap<ulong, ByteRange*>::iterator brIt, brIt_end;
	brIt = brMap.begin();
	brIt_end = brMap.end();
	rdb_stats_available = true;

	for (; brIt != brIt_end; brIt++) {
		if (prev) {
			if (prev->endSeq +1 != brIt->second->startSeq && prev->startSeq != prev->endSeq) {
				//printf("Range not continuous!\n Gap in %lu:%lu - %lu:%lu\n", prev->startSeq, prev->endSeq, brIt->second->startSeq, brIt->second->endSeq);
			}
		}
		prev = brIt->second;

		index++;

		sent_count += brIt->second->sent_count;
		recv_count += brIt->second->received_count;

		// Data lost
		if (brIt->second->sent_count != brIt->second->received_count) {
			bytes_lost += (brIt->second->sent_count - brIt->second->received_count) * brIt->second->byte_count;
		}

		int miss = 0;
		int hit = 0;
		int recv_tmp = 0;
		int send_tmp = 0;

		// Substract the 1 which is the normal transfer of data
		recv_tmp = brIt->second->received_count -1;
		send_tmp = brIt->second->sent_count -1;

		// Retransfers were made
		if (brIt->second->retrans) {
			recv_tmp -= brIt->second->retrans;
			send_tmp -= brIt->second->retrans;
		}

		rdb += send_tmp * brIt->second->byte_count;

		// Bytes were received more than once, RDB...
		if (recv_tmp > 0) {
			miss = recv_tmp * brIt->second->byte_count;
			rdb_byte_miss += miss;
		}

		if ((send_tmp - recv_tmp) > 0) {
			hit = (send_tmp - recv_tmp) * brIt->second->byte_count;
			rdb_byte_hits += hit;
			rdb_packet_hits++;
		}

		if (GlobOpts::print_packets) {

			printf("Byte range (%4lu): %lu - %lu: sent: %d, received: %d, retrans: %d, is_rdb: %d, rdb-miss: %-3d rdb-hit: %-3d", brIt->second->endSeq - brIt->second->startSeq +1,
			       relative_seq(brIt->second->startSeq), relative_seq(brIt->second->endSeq), brIt->second->sent_count, brIt->second->received_count,
			       brIt->second->retrans, brIt->second->is_rdb, miss, hit);

			if (brIt->second->sent_count != brIt->second->received_count) {
				printf("   LOST %d, index: %d", brIt->second->sent_count - brIt->second->received_count, index);
				lost_range_count++;
			}

			if (!brIt->second->retrans && !brIt->second->is_rdb && (miss || hit)) {
				printf(" FAIL (RDB hit/miss calculalation has failed)!");
			}

			if (brIt->second->sent_count > 1)
				lost_tmp += brIt->second->sent_count - 1;
			else {
				// Necessary for correct index when multiple packets in a row are lost
				index += lost_tmp;
				lost_tmp = 0;
			}
			printf("\n");
		}
	}

}


/* Reads all packets from receiver dump into a vector */
void RangeManager::registerRecvDiffs() {
	vector<recvData*>::iterator rit, rit_end;

	/* Store ranges with no corresponding packet
	   on the receiver side, and delete them after
	   traversing all ranges */
	vector<multimap<ulong, Range*>::iterator> delList;

	/* Create map with references to the ranges */
	rit = recvd.begin();
	rit_end = recvd.end();
	multimap<ulong, struct recvData*> rsMap;

	for (; rit != rit_end ; rit++) {
		struct recvData *tmpRd = *rit;
		rsMap.insert(pair<ulong, struct recvData*>(tmpRd->startSeq, tmpRd));

		if ((GlobOpts::print_packets || GlobOpts::rdbDetails) && (tmpRd->payload_len != 0 || 1)) {
			insert_byte_range(tmpRd->startSeq, tmpRd->endSeq, false, false, false, 0);
		}
	}

	if (GlobOpts::print_packets || GlobOpts::rdbDetails)
		calculateRDBStats();

	std::pair <std::multimap<ulong, struct recvData*>::iterator, std::multimap<ulong, struct recvData*>::iterator> ret;

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
		multimap<ulong, struct recvData*>::iterator lowIt, highIt;
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
			struct recvData *tmpRd = lowIt->second;
			int match_count = 0;

			if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
				cerr << "\nProcessing received packet with seq: " <<
					relative_seq(tmpRd->startSeq) << " - " << relative_seq(tmpRd->endSeq) << " | Recvd:"
					 << tmpRd->tv.tv_sec << "." << tmpRd->tv.tv_usec << endl;
				if (GlobOpts::debugLevel == 5) {
					cerr << "absLow: " << relative_seq(absLow) << " - absHigh: " << relative_seq(absHigh) << endl;
				}
			}

			if (GlobOpts::debugLevel == 7) {
				printf("   Checking seq: (%5lu - %5lu)\n", relative_seq(tmpRd->startSeq), relative_seq(tmpRd->endSeq));
			}
			/* If the received packet matches the range */
			if (tmpRd->startSeq <= sndStartSeq && tmpRd->endSeq >= sndEndSeq) {
				/* Set match time to the lowest observed value that
				   matches the range */
				match_count++;

				if (GlobOpts::debugLevel == 7) {
					printf("   Receieved seq: %10lu         -      %10lu\n", relative_seq(tmpRd->startSeq), relative_seq(tmpRd->endSeq));
				}

				if (no_more_matches) {
					printf("Encountered matching packet after the current limit (%d)!!!\n", packet_match_limit);
				}

				if (timercmp(&(tmpRd->tv), &match, <))
					match = tmpRd->tv;
				matched = packet_index;
				it->second->received++;

				if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5) {
					cerr << "Found overlapping recvData:     seq: " <<
						relative_seq(tmpRd->startSeq) << " - " << relative_seq(tmpRd->endSeq) << " - Recvd:"
						 << tmpRd->tv.tv_sec << "." << tmpRd->tv.tv_usec << endl;
				}

				if (tmpRd->startSeq == sndStartSeq && tmpRd->endSeq == sndEndSeq) {

					if (test) {
						printf("               Found exact match (%lu, %lu)\n", tmpRd->startSeq, tmpRd->endSeq);
					}

					if (GlobOpts::debugLevel == 7) {
						printf("               Found exact match");
					}
					it->second->exact_match = 1;
					break;
				}
				else if (tmpRd->startSeq >= sndStartSeq && tmpRd->endSeq <= sndEndSeq) {
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
				struct recvData *tmpRd = rsMap.find(it->second->getStartSeq() +1)->second;
				if (tmpRd->payload_len != 0) {
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

/*
	// Remove invalid ranges
	// Do in reverse so as not to invalidate iterators 
	vector<multimap<ulong, Range*>::iterator>::reverse_iterator dit, dit_end;
	dit = delList.rbegin();
	dit_end = delList.rend();

	//for (; dit != dit_end; dit++) {
	//	delBytes += (*(*dit))->getNumBytes();
	//	ranges.erase(*dit);
	//	//delete *(*dit);
	//}

	// End of the current connection. Free recv data
	//recvd.~vector();
	//free_recv_vector();
*/
}


ulong RangeManager::relative_seq(ulong seq) {
	static ulong wrap_index;
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
			printf("Timvals have not not populated! minTimeStart is zero: %s, minTimeEnd is zero: %s\n", !timerisset(&minTimeStart) ? "Yes" : "No", !timerisset(&minTimeEnd) ? "Yes" : "No");
			warn_with_file_and_linenum(1, __FILE__, __LINE__);
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

void RangeManager::makeCdf(){
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

void RangeManager::printCDF(){
	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = cdf.begin();
	nit_end = cdf.end();

	if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
		cerr << "lowestDiff: " << lowestDiff << endl;
	}

	cout << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / getTotNumBytes();
		printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
	}
}

void RangeManager::printDcCdf(){
	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = dcCdf.begin();
	nit_end = dcCdf.end();

	if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
		cerr << "lowestDcDiff: " << lowestDcDiff << endl;
	}

	/* Do not print cdf for short conns */
	if(drift == -1)
		return;

	cout << "#------ Drift : " << drift << "ms/s ------" << endl;
	cout << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / getTotNumBytes();
		printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
	}
}

void RangeManager::genRFiles(string connKey){
	multimap<ulong, Range*>::iterator it, it_end;
	it = ranges.begin();
	it_end = ranges.end();

	ofstream dcDiff, retr1, retr2, retr3, retr4, retr5, retr6, all;
	stringstream r1fn, r2fn, r3fn, r4fn, r5fn, r6fn, allfn, dcdfn;

	if(!(GlobOpts::aggOnly)){
		r1fn << GlobOpts::prefix << "-1retr-" << connKey << ".dat";
		r2fn << GlobOpts::prefix << "-2retr-" << connKey << ".dat";
		r3fn << GlobOpts::prefix << "-3retr-" << connKey << ".dat";
		r4fn << GlobOpts::prefix << "-4retr-" << connKey << ".dat";
		r5fn << GlobOpts::prefix << "-5retr-" << connKey << ".dat";
		r6fn << GlobOpts::prefix << "-6retr-" << connKey << ".dat";
		allfn << GlobOpts::prefix << "-all-" << connKey << ".dat";

		retr1.open((char*)((r1fn.str()).c_str()), ios::out);
		retr2.open((char*)((r2fn.str()).c_str()), ios::out);
		retr3.open((char*)((r3fn.str()).c_str()), ios::out);
		retr4.open((char*)((r4fn.str()).c_str()), ios::out);
		retr5.open((char*)((r5fn.str()).c_str()), ios::out);
		retr6.open((char*)((r6fn.str()).c_str()), ios::out);
		all.open((char*)((allfn.str()).c_str()), ios::out);
	}

	for(; it != it_end; it++){

		if(it->second->getNumRetrans() == 1){
			if ( it->second->getDiff() > 0){
				GlobStats::retr1.push_back(it->second->getDiff());
				if(!(GlobOpts::aggOnly))
					retr1 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getNumRetrans() == 2) {
			if (it->second->getDiff() > 0) {
				GlobStats::retr2.push_back(it->second->getDiff());
				if(!(GlobOpts::aggOnly))
					retr2 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getNumRetrans() == 3) {
			if (it->second->getDiff() > 0) {
				GlobStats::retr3.push_back(it->second->getDiff());
				if (!(GlobOpts::aggOnly))
					retr3 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getNumRetrans() == 4) {
			if ( it->second->getDiff() > 0){
				GlobStats::retr4.push_back(it->second->getDiff());
				if(!(GlobOpts::aggOnly))
					retr4 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getNumRetrans() == 5) {
			if ( it->second->getDiff() > 0){
				GlobStats::retr5.push_back(it->second->getDiff());
				if(!(GlobOpts::aggOnly))
					retr5 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getNumRetrans() == 6) {
			if ( it->second->getDiff() > 0){
				GlobStats::retr6.push_back(it->second->getDiff());
				if(!(GlobOpts::aggOnly))
					retr6 << it->second->getDiff() << endl;
			}
		}

		if (it->second->getDiff() > 0) {
			GlobStats::all.push_back(it->second->getDiff());
			if(!(GlobOpts::aggOnly))
				all << it->second->getDiff() << endl;
		}
	}

	if(!(GlobOpts::aggOnly)){
		retr1.close();
		retr2.close();
		retr3.close();
		retr4.close();
		all.close();
	}
}
