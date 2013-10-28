#include "Connection.h"

/* Methods for class Connection */
Connection::Connection(struct in_addr src_ip, uint16_t src_port,
		       struct in_addr dst_ip, uint16_t dst_port,
		       uint32_t seq){
  nrPacketsSent              = 0;
  nrDataPacketsSent          = 0;
  totPacketSize              = 0;
  totBytesSent               = 0;
  totRDBBytesSent            = 0;
  totNewDataSent             = 0;
  nrRetrans                  = 0;
  totRetransBytesSent        = 0;
  srcIp                      = src_ip;
  srcPort                    = src_port;
  dstIp                      = dst_ip;
  dstPort                    = dst_port;
  lastLargestEndSeq          = 0;
  lastLargestSeqAbsolute     = seq;
  lastLargestRecvEndSeq      = 0;
  lastLargestRecvSeqAbsolute = seq;
  lastLargestAckSeq          = 0;
  lastLargestAckSeqAbsolute  = seq;
  firstSeq                   = seq;
  curSeq                     = 0;
  bundleCount                = 0;
  memset(&firstSendTime, 0, sizeof(firstSendTime));
  memset(&endTime, 0, sizeof(endTime));
  rm = new RangeManager(this, seq);
}

Connection::~Connection() {
	delete rm;
}

/* Count bundled and retransmitted packets from sent data */
void Connection::registerSent(struct sendData* sd) {
  totPacketSize += sd->totalSize;
  nrPacketsSent++;

  // This is ack
  if (sd->payloadSize == 0) {
	  return;
  }

  if (sd->endSeq > lastLargestEndSeq) { /* New data */
	  if (GlobOpts::debugLevel == 6) {
		  printf("New Data - sd->endSeq: %lu > lastLargestEndSeq: %lu, sd->seq: %lu, curSeq: %lu, len: %u\n",
			 rm->relative_seq(sd->endSeq), rm->relative_seq(lastLargestEndSeq),
			 rm->relative_seq(sd->seq), rm->relative_seq(curSeq), sd->payloadSize);
	  }

	  // Same seq as previous packet
	  if ((sd->seq == curSeq) && (sd->endSeq > lastLargestEndSeq)) {
		  bundleCount++;
		  totRDBBytesSent += (lastLargestEndSeq - sd->seq +1);
		  totNewDataSent += (sd->endSeq - lastLargestEndSeq);
		  sd->is_rdb = true;
	  } else if ((sd->seq > curSeq) && (sd->seq < lastLargestEndSeq) && (sd->endSeq > lastLargestEndSeq)) {
		  totRDBBytesSent += (lastLargestEndSeq - sd->seq +1);
		  totNewDataSent += (sd->endSeq - lastLargestEndSeq);
		  bundleCount++;
		  sd->is_rdb = true;
	  }
	  else {
		  // Should only happen on the first call when curSeq and lastLargestEndSeq are 0
		  totNewDataSent += sd->payloadSize;
	  }
	  lastLargestEndSeq = sd->endSeq;
	  lastLargestSeqAbsolute = sd->seq_absolute + sd->payloadSize;
  } else if (curSeq > 0 && sd->seq <= curSeq) { /* All seen before */
	  if (GlobOpts::debugLevel == 6) {
		  printf("\nRetrans - curSeq: %lu > 0 && sd->seq: %lu <= curSeq: %lu\n", rm->relative_seq(curSeq), rm->relative_seq(sd->seq), rm->relative_seq(curSeq));
	  }
	  nrRetrans++;
	  totRetransBytesSent += sd->payloadSize;
	  sd->retrans = true;
  }

  else {
	  nrRetrans++;
	  totRetransBytesSent += sd->payloadSize;
	  sd->retrans = true;
	  if (GlobOpts::debugLevel == 6) {
		  printf("\n\nNeither!!----------------------------------\n");
		  printf("Retrans - curSeq: %lu > 0 && sd->seq: %lu <= curSeq: %lu\n", rm->relative_seq(curSeq), rm->relative_seq(sd->seq), rm->relative_seq(curSeq));
		  printf("New Data - sd->endSeq: %lu > lastLargestEndSeq: %lu\n", rm->relative_seq(sd->endSeq), rm->relative_seq(lastLargestEndSeq));
	  }
  }

  if (sd->payloadSize) {
	  nrDataPacketsSent++;
	  curSeq = sd->seq;
  }
  totBytesSent += sd->payloadSize;
}

/* Process range for outgoing packet */
Range* Connection::registerRange(struct sendData* sd) {
	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
		static timeval offset;
		if (firstSendTime.tv_sec == 0 && firstSendTime.tv_usec == 0) {
			firstSendTime = sd->time;
		}
		timersub(&(sd->time), &firstSendTime, &offset);
		cerr << "\nRegistering new outgoing. Conn: " << getConnKey() << " Seq: " << rm->relative_seq(sd->seq) << " - " << rm->relative_seq(sd->endSeq) <<  " Payload: " << sd->payloadSize << endl;
		cerr << "Time offset: Secs: " << offset.tv_sec << "." << offset.tv_usec << endl;
	}

	Range *r = rm->insertSentRange(sd);

	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5) {
		cerr << "Last range: seq: " << rm->relative_seq(rm->getLastRange()->getStartSeq())
		     << " - " << rm->relative_seq(rm->getLastRange()->getEndSeq()) << " - size: "
		     << rm->getLastRange()->getEndSeq() - rm->getLastRange()->getStartSeq()
		     << endl;
	}
	return r;
}

/* Register times for first ACK of each byte */
bool Connection::registerAck(ulong ack, timeval* tv){
	static bool ret;
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		timeval offset;
		timersub(tv, &firstSendTime, &offset);
		cerr << endl << "Registering new ACK. Conn: " << getConnKey() << " Ack: " << rm->relative_seq(ack) << endl;
		cerr << "Time offset: Secs: " << offset.tv_sec << " uSecs: " << offset.tv_usec << endl;
	}

	ret = rm->processAck(ack, tv);

	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		if(rm->getHighestAcked() != NULL){
			cerr << "highestAcked: startSeq: " << rm->relative_seq(rm->getHighestAcked()->getStartSeq()) << " - endSeq: "
			     << rm->relative_seq(rm->getHighestAcked()->getEndSeq()) << " - size: "
			     << rm->getHighestAcked()->getEndSeq() - rm->getHighestAcked()->getStartSeq() << endl;
		}
	}
	return ret;
}

/* Generate statistics for each connection.
   update aggregate stats if requested */
void Connection::addPacketStats(struct connStats* cs) {
	cs->duration += rm->getDuration();
	cs->totBytesSent += totBytesSent;
	cs->totRetransBytesSent += totRetransBytesSent;
	cs->totPacketSize += totPacketSize;
	cs->nrPacketsSent += nrPacketsSent;
	cs->nrDataPacketsSent += nrDataPacketsSent;
	cs->nrRetrans += nrRetrans;
	cs->bundleCount += bundleCount;
	cs->totUniqueBytes += getNumUniqueBytes();
	cs->redundantBytes += rm->getRedundantBytes();
	// RDB stats
	cs->rdb_bytes_sent = totRDBBytesSent;

	if (rm->rdb_stats_available) {
		cs->rdb_stats_available = true;
		cs->rdb_packet_misses += (bundleCount - rm->rdb_packet_hits);
		cs->rdb_packet_hits += rm->rdb_packet_hits;
		cs->rdb_byte_misses += rm->rdb_byte_miss;
		cs->rdb_byte_hits += rm->rdb_byte_hits;
	}
}

/* Generate statistics for bytewise latency */
void Connection::genBytesLatencyStats(struct byteStats* bs){
	/* Iterate through vector and gather data */
	rm->genStats(bs);
	if (bs->nrRanges > 0)
		bs->avgLat = bs->cumLat / bs->nrRanges;
}

void Connection::printPacketDetails() {

	multimap<ulong, Range*>::iterator it, it_end;
	it = rm->ranges.begin();
	it_end = rm->ranges.end();

	bool received = rm->hasReceiveData();

	for (; it != it_end; it++) {

		if (received && !it->second->isExactMatched()) {
			printf("Lost  seq: %5lu - (%5lu) - %5lu, len: %4d, retrans: %d, ACK latency: %d\n",
			       rm->relative_seq(it->second->getRDBSeq()), rm->relative_seq(it->second->getStartSeq()),
			       rm->relative_seq(it->second->getEndSeq()), it->second->getNumBytes(), it->second->getNumRetrans(), it->second->getDiff());
		} else {
			printf("----  seq: %5lu - (%5lu) - %5lu, len: %4d, retrans: %d, ACK latency: %d\n",
				   rm->relative_seq(it->second->getRDBSeq()), rm->relative_seq(it->second->getStartSeq()),
			       rm->relative_seq(it->second->getEndSeq()), it->second->getNumBytes(), it->second->getNumRetrans(), it->second->getDiff());
		}
	}
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

void Connection::registerRecvd(struct sendData *sd){
  /* Insert range into datastructure */
  rm->insertRecvRange(sd);
}

void Connection::makeCDF(){
  rm->registerRecvDiffs();
  rm->makeCdf();
}

void Connection::printCDF(ofstream *stream) {
	*stream << endl;
	*stream << "#------CDF - Conn: " << getConnKey() << " --------" << endl;
	rm->printCDF(stream);
}

void Connection::printDcCdf(ofstream *stream) {
	*stream << endl;
	*stream << "#------Drift-compensated CDF - Conn: " << getConnKey() << " --------" << endl;
	rm->printDcCdf(stream);
}

void Connection::makeDcCdf(){
	if (rm->calcDrift() == 0) {
		rm->registerDcDiffs();
		rm->makeDcCdf();
	}
}

void Connection::genRFiles() {
	rm->genRFiles(getConnKey());
}

ulong Connection::getNumUniqueBytes() {
	multimap<ulong, Range*>::iterator it, it_end = rm->ranges.end();
	ulong first_data_seq = 0, last_data_seq = 0;

	for (it = rm->ranges.begin(); it != it_end; it++) {
		if (it->second->getNumBytes()) {
			first_data_seq = it->second->getStartSeq();
			break;
		}
	}

	multimap<ulong, Range*>::reverse_iterator rit, rit_end = rm->ranges.rend();
	for (rit = rm->ranges.rbegin(); rit != rit_end; rit++) {
		if (rit->second->getNumBytes()) {
			last_data_seq = rit->second->getEndSeq();
			break;
		}
	}
	ulong unique_data_bytes = last_data_seq - first_data_seq + 1;
	return unique_data_bytes;
}

string Connection::getConnKey(){
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(srcIp), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(dstIp), dst_ip, INET_ADDRSTRLEN);

  /* Generate snd IP/port + rcv IP/port string to use as key */
  stringstream connKey;
  connKey << src_ip
	  << "-" << srcPort
	  << "-" << dst_ip
	  << "-" << dstPort;
  return connKey.str();
}

string Connection::getSrcIp(){
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(srcIp), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(dstIp), dst_ip, INET_ADDRSTRLEN);

  /* Generate snd IP/port + rcv IP/port string to use as key */
  stringstream sip;
  sip << src_ip;
  return sip.str();
}

string Connection::getDstIp(){
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(srcIp), src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(dstIp), dst_ip, INET_ADDRSTRLEN);

  /* Generate snd IP/port + rcv IP/port string to use as key */
  stringstream dip;
  dip << dst_ip;
  return dip.str();
}
