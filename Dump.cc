#include "Dump.h"

int GlobStats::totNumBytes;
map<ConnectionMapKey*, string, ConnectionKeyComparator> connKeys;

/* Methods for class Dump */
Dump::Dump( string src_ip, string dst_ip, int src_port, int dst_port, string fn ){
  srcIp = src_ip;
  dstIp = dst_ip;
  srcPort = src_port;
  dstPort = dst_port;
  filename = fn;
  sentPacketCount = 0;
  sentBytesCount = 0;
  recvPacketCount = 0;
  recvBytesCount = 0;
  ackCount = 0;
}

string getConnKey(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort) {
	static struct ConnectionMapKey connKey;
	static map<ConnectionMapKey*, string>::iterator it;
	static char src_ip_buf[INET_ADDRSTRLEN];
	static char dst_ip_buf[INET_ADDRSTRLEN];
	memcpy(&connKey.ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKey.ip_dst, dstIp, sizeof(struct in_addr));
	connKey.src_port = *srcPort;
	connKey.dst_port = *dstPort;

	it = connKeys.find(&connKey);
	// Returning the existing connection key
	if (it != connKeys.end()) {
		return it->second;
	}

	inet_ntop(AF_INET, srcIp, src_ip_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dstIp, dst_ip_buf, INET_ADDRSTRLEN);

	stringstream connKeyTmp;
	connKeyTmp << src_ip_buf << "-" << ntohs(*srcPort) << "-" << dst_ip_buf << "-" << ntohs(*dstPort);
	ConnectionMapKey *connKeyToInsert = new ConnectionMapKey();
	memcpy(&connKeyToInsert->ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKeyToInsert->ip_dst, dstIp, sizeof(struct in_addr));
	connKeyToInsert->src_port = connKey.src_port;
	connKeyToInsert->dst_port = connKey.dst_port;
	connKeys[connKeyToInsert] = connKeyTmp.str();
	return connKeyTmp.str();
}

/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender() {
	int packetCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr h;
	const u_char *data;
	map<string, Connection*>::iterator it, it_end;

	pcap_t *fd = pcap_open_offline(filename.c_str(), errbuf);
	if ( fd == NULL ) {
		cerr << "pcap: Could not open file" << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	/* Set up pcap filter to include only outgoing tcp
	   packets with correct ip and port numbers.
	*/

	/* TODO: Add options to crop dumpfiles from front or back with n
	   minutes */

	struct bpf_program compFilter;
	stringstream filterExp;
	filterExp << "tcp && src host " << srcIp;
	if (!srcPort == 0)
		filterExp << " && src port " << srcPort;
	if (!dstIp.empty())
		filterExp << " && dst host " << dstIp;
	if (!dstPort == 0)
		filterExp << " && dst port " << dstPort;
	// Earlier, only packets with TCP payload were used.
	//filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";

	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
		cerr << "pcap filter expression: " << (char*)((filterExp.str()).c_str()) << endl;

	/* Filter to get outgoing packets */
	if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	printf("Processing sent packets...\n");
	printf("Using filter: '%s'\n", filterExp.str().c_str());

	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd, &h);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd, errMsg);
		} else {
			processSent(&h, data); /* Sniff packet */
			packetCount++;
		}
	} while(data != NULL);

	printf("Finished processing sent packets...\n");

	pcap_close(fd);

	/* DEBUG: Validate range */
	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
		cerr << "---------------Begin first validation--------------" << endl;

	it_end = conns.end();
	for (it = conns.begin(); it != it_end; it++) {
		it->second->validateRanges();
	}
	if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
		cerr << "---------------End of first validation--------------" << endl;

	pcap_t *fd2 = pcap_open_offline(filename.c_str(), errbuf);
	if (fd2 == NULL) {
		cerr << "pcap: Could not open file" << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	filterExp.str("");
	filterExp << "tcp";
	if (!dstIp.empty())
		filterExp << " && src host " << dstIp;
	if (!dstPort == 0)
		filterExp << " && src port " << dstPort;
	filterExp << " && dst host " << srcIp;
	if (!srcPort == 0)
		filterExp << " && dst port " << srcPort;
	filterExp << " && ((tcp[tcpflags] & tcp-syn) != tcp-syn)"
			  << " && ((tcp[tcpflags] & tcp-fin) != tcp-fin)"
			  << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
		cerr << "pcap filter expression: " << (char*)((filterExp.str()).c_str()) << endl;

	if (pcap_compile(fd2, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd2, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	printf("Processing acknowledgements...\n");
	packetCount = 0;
	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd2, &h);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd2, errMsg);
		} else {
			processAcks(&h, data); /* Sniff packet */
			packetCount++;
		}
	} while (data != NULL);

	pcap_close(fd2);

	printf("Finished processing acknowledgements...\n");

	/* DEBUG: Validate ranges */
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
		cerr << "---------------Begin second validation--------------" << endl;
	it_end = conns.end();
	for (it = conns.begin(); it != it_end; it++) {
		it->second->validateRanges();
	}

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
		cerr << "---------------End of second validation--------------" << endl;
}


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::printStatistics() {

	/* Initiate struct for aggregate stats */
	struct connStats cs, csAggregated;
	memset(&cs, 0, sizeof(struct connStats));
	memset(&csAggregated, 0, sizeof(struct connStats));

	float aggrCumAvgLat = 0;
	struct byteStats bsAggregated;
	memset(&bsAggregated, 0, sizeof(struct byteStats));
	bsAggregated.minLat = (numeric_limits<int>::max)();

	// Print stats for each connection or aggregated
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->addPacketStats(&cs);
		cIt->second->addPacketStats(&csAggregated);

		/* Initialize bs struct */
		struct byteStats bs;
		memset(&bs, 0, sizeof(struct byteStats));
		bs.minLat = (numeric_limits<int>::max)();
		cIt->second->genBytesLatencyStats(&bs);

		if (!(GlobOpts::aggOnly) && !(GlobOpts::aggInfo)) {
			printf("\nSTATS FOR CONN: %s:%u -> %s:%u\n", cIt->second->getSrcIp().c_str(), cIt->second->srcPort, cIt->second->getDstIp().c_str(), cIt->second->dstPort);
			printPacketStats(&cs, &bs);
			memset(&cs, 0, sizeof(struct connStats));
		}

		if (!(GlobOpts::aggOnly) && !(GlobOpts::aggInfo)) {
			cout << "\nBytewise latency - Conn: " <<  cIt->second->getConnKey() << endl;
			printBytesLatencyStats(&bs);
		}

		if (GlobOpts::aggregate) {
			if (bs.minLat < bsAggregated.minLat)
				bsAggregated.minLat = bs.minLat;
			if (bs.maxLat > bsAggregated.maxLat)
				bsAggregated.maxLat = bs.maxLat;
			aggrCumAvgLat += bs.cumLat;

			bsAggregated.retrans[0] += bs.retrans[0];
			bsAggregated.retrans[1] += bs.retrans[1];
			bsAggregated.retrans[2] += bs.retrans[2];
			if (bsAggregated.maxRetrans < bs.maxRetrans) {
				bsAggregated.maxRetrans = bs.maxRetrans;
			}
		}
	}

	bsAggregated.avgLat = aggrCumAvgLat / csAggregated.nrDataPacketsSent;
	csAggregated.duration /= conns.size();

	if (GlobOpts::aggregate || GlobOpts::aggInfo) {
		if (csAggregated.nrPacketsSent) { /* To avoid division by 0 */

			cout << "\n\nAggregate Statistics for " << conns.size() << " connections:" << endl;
			printf("&csAggregated2: %p\n", &csAggregated);
			printf("bsAggregated.avgLength: %u\n", bsAggregated.avgLength);
			printPacketStats(&csAggregated, &bsAggregated);

			cout << "--------------------------------------------------" <<endl;
			/* Print Aggregate bytewise latency */


			cout << "Bytewise (application layer) latency" << endl;
			printBytesLatencyStats(&bsAggregated);
		}
	}
}


/* Generate statistics for each connection.
   update aggregate stats if requested */
void Dump::printPacketStats(struct connStats *cs, struct byteStats *bs) {
	printf("Duration: %u seconds (%f hours)\n"			\
	       "Total packets sent                           : %10d\n"	\
	       "Total data packets sent                      : %10d\n"	\
	       "Total pure acks (no payload) (Incl. SYN/FIN) : %10d\n"	\
	       "Number of retransmissions                    : %10d\n"	\
	       "Number of packets with bundled segments      : %10d\n"	\
	       "Total bytes sent (payload)                   : %10d\n"	\
	       "Number of unique bytes                       : %10d\n"	\
	       "Number of retransmitted bytes                : %10d\n"	\

	       "Estimated loss rate based on retransmissions : %10f %%\n" \
	       "Payload stats:\n"					\
	       "  Average size                               : %-10d\n",
	       cs->duration, ((float) cs->duration / 60 / 60),
	       cs->nrPacketsSent, cs->nrDataPacketsSent, cs->nrPacketsSent - cs->nrDataPacketsSent, cs->nrRetrans, cs->bundleCount, cs->totBytesSent,
	       cs->totUniqueBytes, cs->totRetransBytesSent,
	       (((float) cs->nrRetrans / cs->nrPacketsSent) * 100),(int) floorf((float) (cs->totBytesSent / cs->nrDataPacketsSent)));


	if (bs != NULL) {
		printf("  Minimum size                               : %-10d\n" \
		       "  Maximum size                               : %-10d\n",
		       bs->minLength, bs->maxLength);

		if (bs->quartilesLength) {
			printf("  Standard deviation                         : %f\n" \
			       "  First  quartile (25th percentile)          : %f\n" \
			       "  Second quartile (50th percentile) (median) : %f\n" \
			       "  Third  quartile (75th percentile)          : %f\n",
			       bs->stdevLength,
			       bs->quartilesLength->first,
			       bs->quartilesLength->second,
			       bs->quartilesLength->third);
		}
	}

	if (GlobOpts::incTrace) {
		printf("Number of retransmitted bytes                : %10d\n"	\
		       "Redundancy                                   : %10f %%\n",
		       cs->redundantBytes, ((float) cs->redundantBytes / cs->totUniqueBytes) * 100);
	} else {
		cout << "Redundancy: "
		     << ((float) (cs->totBytesSent - cs->totUniqueBytes) / cs->totBytesSent) * 100
		     << "\%" << endl;
	}

	if (cs->rdb_bytes_sent) {
		printf("RDB stats:\n");
		printf("RDB packets:       %10d (%f%% of data packets sent)\n", cs->bundleCount, ((double) cs->bundleCount) / cs->nrDataPacketsSent * 100);
		printf("RDB bytes bundled: %10d (%f%% of total bytes sent)\n", cs->rdb_bytes_sent, ((double) cs->rdb_bytes_sent) / cs->totBytesSent * 100);

		if (cs->rdb_stats_available) {
			printf("RDB packet hits:   %10d (%f%% of RDB packets sent)\n", cs->rdb_packet_hits, ((double) cs->rdb_packet_hits) / cs->bundleCount * 100);
			printf("RDB packet misses: %10d (%f%% of RDB packets sent)\n", cs->rdb_packet_misses, ((double) cs->rdb_packet_misses) / cs->bundleCount * 100);
			printf("RDB byte   misses: %10d (%f%% of RDB bytes)\n", cs->rdb_byte_misses, ((double) cs->rdb_byte_misses) / (cs->rdb_bytes_sent) * 100);
			printf("RDB byte     hits: %10d (%f%% of RDB bytes)\n", cs->rdb_byte_hits, ((double) cs->rdb_byte_hits) / (cs->rdb_bytes_sent) * 100);
		}
	}
	cout << "--------------------------------------------------" << endl;
}


/* Generate statistics for bytewise latency */
void Dump::printBytesLatencyStats(struct byteStats* bs) {
	cout << "Minimum latency                              : " << bs->minLat << " ms" << endl;
	cout << "Average latency                              : " << bs->avgLat << " ms" << endl;
	cout << "Maximum latency                              : " << bs->maxLat << " ms" << endl;
	cout << "Standard deviation                           : " << bs->stdevLat << " ms" << endl;
	if (bs->quartilesLat) {
		cout << "First  quartile (25th percentile)            : " << bs->quartilesLat->first << endl;
		cout << "Second quartile (50th percentile) (median)   : " << bs->quartilesLat->second << endl;
		cout << "Third  quartile (75th percentile)            : " << bs->quartilesLat->third << endl;
	}
	cout << "--------------------------------------------------" << endl;
	cout << "Occurrences of 1. retransmission : " << bs->retrans[0] << endl;
	cout << "Occurrences of 2. retransmission : " << bs->retrans[1] << endl;
	cout << "Occurrences of 3. retransmission : " << bs->retrans[2] << endl;
	cout << "Max retransmissions              : " << bs->maxRetrans << endl;
	cout << "==================================================" << endl;
}

/* Process outgoing packets */
void Dump::processSent(const struct pcap_pkthdr* header, const u_char *data) {
	static const struct sniff_ethernet *ethernet; /* The ethernet header */
	static const struct sniff_ip *ip; /* The IP header */
	static const struct sniff_tcp *tcp; /* The TCP header */
	static Connection *tmpConn;
	static u_int ipSize;
	static u_int ipHdrLen;
	static u_int tcpHdrLen;
	static string connKey;
	static struct sendData sd;

	/* Finds the different headers+payload */
	ethernet = (struct sniff_ethernet*) data;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipSize = ntohs(ip->ip_len);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	tcpHdrLen = TH_OFF(tcp) * 4;

	connKey = getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport);

	/* Check if connection exists. If not, create a new */
	if (conns.count(connKey) == 0){
		tmpConn = new Connection(ip->ip_src, ntohs(tcp->th_sport), ip->ip_dst,
					 ntohs(tcp->th_dport), ntohl(tcp->th_seq) );
		conns.insert(pair<string, Connection*>(connKey, tmpConn));
		if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
			cerr << "created new Connection with key: " << connKey << endl;
	} else {
		tmpConn = conns[connKey];
	}

	/* Prepare packet data struct */
	sd.totalSize    = header->len;
	sd.ipSize       = ipSize;
	sd.ipHdrLen     = ipHdrLen;
	sd.tcpHdrLen    = tcpHdrLen;
	sd.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.time         = header->ts;
	sd.seq_absolute = ntohl(tcp->th_seq);
	sd.seq = get_relative_sequence_number(sd.seq_absolute, tmpConn->firstSeq, tmpConn->lastLargestEndSeq, tmpConn->lastLargestSeqAbsolute);
	sd.endSeq  = sd.seq + sd.payloadSize;
	sd.retrans = false;
	sd.is_rdb  = false;

	if (sd.payloadSize > 0) {
		sd.endSeq -= 1;
	}

	/* define/compute tcp payload (segment) offset */
	sd.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);

	sentPacketCount++;
	sentBytesCount += sd.payloadSize;

	tmpConn->registerSent(&sd);
	tmpConn->registerRange(&sd);
}


// Used to test if a sequence number comes after another
// These handle when the newest sequence number has wrapped
static inline bool before(uint32_t seq1, uint32_t seq2) {
	return (signed int) (seq1 - seq2) < 0;
}

static inline bool after_or_equal(uint32_t seq1, uint32_t seq2) {
	return (signed int) (seq2 - seq1) >= 0;
}


/**
 * This function generates the relative sequence number of packets read from pcap files.
 *
 * seq:                The sequence number of the packet
 * firstSeq:           The first sequence number in the stream
 * largestSeq:         The largest relative sequence number that has been read for this stream
 * largestSeqAbsolute: The largest absolute (raw) sequence number that has been read for this stream
 *
 * Returns the relative sequence number or ULONG_MAX if it failed.
**/
ulong Dump::get_relative_sequence_number(uint32_t seq, uint32_t firstSeq, ulong largestSeq, uint32_t largestSeqAbsolute) {
	static ulong wrap_index;
	static ulong seq_relative;
	wrap_index = firstSeq + largestSeq;

	// Either seq has wrapped, or a retrans (or maybe reorder if netem is run on sender machine)
	if (seq < largestSeqAbsolute) {
		// This is an earlier sequence number
		if (before(seq, largestSeqAbsolute)) {
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
		// This is newer seq
		if (after_or_equal(largestSeqAbsolute, seq)) {
			wrap_index += (seq - largestSeqAbsolute);
		}
		// Acks older data than largestAckSeqAbsolute, largestAckSeqAbsolute has wrapped.
		else {
			wrap_index -= (0 - seq) - largestSeqAbsolute;
		}
	}
	wrap_index /= 4294967295;
	seq_relative = seq + (wrap_index * 4294967296) - firstSeq;
	if (seq_relative > 9999999999) {
		return ULONG_MAX;
	}
	return seq_relative;
}

/* Process incoming ACKs */
void Dump::processAcks(const struct pcap_pkthdr* header, const u_char *data) {
	static const struct sniff_ip *ip; /* The IP header */
	static const struct sniff_tcp *tcp; /* The TCP header */
	static timeval hdrTv;
	static u_int ipHdrLen;
	static map<string, Connection*>::iterator it;
	static uint32_t ack;
	static ulong ack_relative;
	static bool ret;
	hdrTv = header->ts;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);

	string connKey = getConnKey(&ip->ip_dst, &ip->ip_src, &tcp->th_dport, &tcp->th_sport);

	/* It should not be possible that the connection is not yet created */
	/* If lingering ack arrives for a closed connection, this may happen */
	it = conns.find(connKey);
	if (it == conns.end()) {
		cerr << "Ack for unregistered connection found. Conn: "
		     << connKey << " - Ignoring." << endl;
		return;
	}
	ack = ntohl(tcp->th_ack);
	ack_relative = get_relative_sequence_number(ack, it->second->firstSeq, it->second->lastLargestAckSeq, it->second->lastLargestAckSeqAbsolute);

	ret = it->second->registerAck(ack_relative, &hdrTv);
	if (!ret) {
		printf("DUMP - failed to register ACK!\n");
	}
	else {
		it->second->lastLargestAckSeqAbsolute = ack;
		it->second->lastLargestAckSeq = ack_relative;

	}
	ackCount++;
}

/* Analyse receiver dump - create CDFs */
void Dump::processRecvd(string recvFn) {
  int packetCount = 0;
  string tmpSrcIp = srcIp;
  string tmpDstIp = dstIp;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr h;
  const u_char *data;
  map<uint16_t, Connection*>::iterator it, it_end;

  printf("Processing receiver dump...\n");

  if (!GlobOpts::sendNatIP.empty()) {
    cerr << "sender side NATing handled" << endl;
    tmpSrcIp = GlobOpts::sendNatIP;
	//srcIp = GlobOpts::sendNatIP;
    cerr << "srcIp: " << srcIp << endl;
    cerr << "tmpSrcIp: " << tmpSrcIp << endl;
  }

  if (!GlobOpts::recvNatIP.empty()) {
    cerr << "receiver side NATing handled" << endl;
    tmpDstIp = GlobOpts::recvNatIP;
    cerr << "dstIp: " << dstIp << endl;
    cerr << "tmpDstIp: " << tmpDstIp << endl;
  }

  char *src_ip_buf = NULL;
  char *dst_ip_buf = NULL;
  if (!tmpSrcIp.empty())
	  src_ip_buf = strdup(tmpSrcIp.c_str());
  if (!tmpDstIp.empty())
	  dst_ip_buf = strdup(tmpDstIp.c_str());

  pcap_t *fd = pcap_open_offline(recvFn.c_str(), errbuf);
  if ( fd == NULL ) {
    cerr << "pcap: Could not open file" << recvFn << endl;
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  /* Set up pcap filter to include only incoming tcp
     packets with correct IP and port numbers.
     We exclude packets with no TCP payload. */
  struct bpf_program compFilter;
  stringstream filterExp;

  filterExp.str("");
  filterExp << "tcp";
  if (!tmpSrcIp.empty())
	  filterExp << " && src host " << tmpSrcIp;
  if (!tmpDstIp.empty())
	  filterExp << " && dst host " << tmpDstIp;
  if (!dstPort == 0)
	  filterExp << " && dst port " << dstPort;

  //filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";

//filterExp << "tcp && src host " << tmpSrcIp << " && dst host "
//	    << tmpDstIp << " && dst port " << dstPort
//	    << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";

  /* Filter to get outgoing packets */
  if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
	  fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  if (pcap_setfilter(fd, &compFilter) == -1) {
	  fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
	  pcap_close(fd);
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  printf("Using filter: '%s'\n", filterExp.str().c_str());

  /* Sniff each sent packet in pcap tracefile: */
  do {
	  data = (const u_char *) pcap_next(fd, &h);
	  if (data == NULL) {
		  if (packetCount == 0) {
//			  char errMsg[50];
			  printf("No packets found!\n");
		  }
		  //pcap_perror(fd, errMsg);
	  } else {
		  processRecvd(&h, data); /* Sniff packet */
		  packetCount++;
	  }
  } while(data != NULL);

  pcap_close(fd);

  /* Traverse ranges in senderDump and compare to
     corresponding bytes / ranges in receiver ranges
     place timestamp diffs in buckets */
  makeCDF();

  if ((GlobOpts::aggOnly))
	  printCDF();

  /* Calculate clock drift for all eligible connections
     eligible: more than 500 ranges &&
     more than 2 minutes duration
	 make drift compensated CDF*/
  makeDcCdf();

  if ((GlobOpts::aggOnly))
	  printDcCdf();

  if(GlobOpts::aggregate){
	  printAggCdf();
	  printAggDcCdf();
  }
}

/* Process packets */
void Dump::processRecvd(const struct pcap_pkthdr* header, const u_char *data) {
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  static Connection *tmpConn;

    /* Finds the different headers+payload */
  ethernet = (struct sniff_ethernet*)(data);
  ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
  u_int ipSize = ntohs(ip->ip_len);
  u_int ipHdrLen = IP_HL(ip)*4;
  tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
  u_int tcpHdrLen = TH_OFF(tcp)*4;

  string connKey = getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport);

  /* It should not be possible that the connection is not yet created */
  /* If lingering ack arrives for a closed connection, this may happen */
  if (conns.count(connKey) == 0){
	  cerr << "Connection found in recveiver dump that does not exist in sender: " << connKey << ". Maybe NAT is in effect?  Exiting." << endl;
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  tmpConn = conns[connKey];

  /* Prepare packet data struct */
  struct sendData sd;
  sd.totalSize   = header->len;
  sd.ipSize      = ipSize;
  sd.ipHdrLen    = ipHdrLen;
  sd.tcpHdrLen   = tcpHdrLen;
  sd.payloadSize = ipSize - (ipHdrLen + tcpHdrLen);
  sd.seq_absolute = ntohl(tcp->th_seq);
  sd.seq         = get_relative_sequence_number(sd.seq_absolute, tmpConn->firstSeq, tmpConn->lastLargestRecvEndSeq, tmpConn->lastLargestRecvSeqAbsolute);
  sd.endSeq      = sd.seq + sd.payloadSize;
  sd.time        = header->ts;

  if (sd.seq == ULONG_MAX) {
	  if (tmpConn->lastLargestRecvEndSeq == 0) {
		  printf("Found invalid sequence numbers in beginning of receive dump. Probably the sender tcpdump didn't start in time to save this packets\n");
	  }
	  else {
		  printf("Found invalid sequence number in received data!: %lu -> %lu\n", sd.seq_absolute, sd.seq);
	  }
	  return;
  }

  /* define/compute tcp payload (segment) offset */
  sd.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);

  //char *str = (char*) malloc(sd.data_len + 1);
  //snprintf(str, sd.data_len + 1, "%s", sd.data);
  //printf("Data not found on receiver (%u): %s\n", sd.data_len, str);
  //free(str);

  recvPacketCount++;
  recvBytesCount += sd.payloadSize;

  tmpConn->registerRecvd(&sd);
}

void Dump::makeCDF(){
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		printf("MakeCDF on conn %s\n", cIt->second->getConnKey().c_str());
		cIt->second->makeCDF();
	}
}

void Dump::printCDF(){
  map<string, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->printCDF();
  }
}

void Dump::printDcCdf(){
  map<string, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->printDcCdf();
  }
}

void Dump::printAggCdf(){
  map<const int, int>::iterator nit, nit_end;
  double cdfSum = 0;
  nit = GlobStats::cdf.begin();
  nit_end = GlobStats::cdf.end();

  cout << endl << endl << "#Aggregated CDF:" << endl;
  cout << "#Relative delay      Percentage" << endl;
  for(; nit != nit_end; nit++){
    cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
    printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
  }
}

void Dump::printAggDcCdf(){
  map<const int, int>::iterator nit, nit_end;
  double cdfSum = 0;
  nit = GlobStats::dcCdf.begin();
  nit_end = GlobStats::dcCdf.end();

  cout << endl << "#Aggregated, drift-compensated CDF:" << endl;
  cout << "#------ Average drift : " << GlobStats::avgDrift << "ms/s ------" << endl;
  cout << "#Relative delay      Percentage" << endl;
  for(; nit != nit_end; nit++){
    cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
    printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
  }
}

void Dump::makeDcCdf(){
  map<string, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->makeDcCdf();
  }
}

void Dump::printDumpStats() {
  cout << endl;
  cout << "General info for entire dump:" << endl;
  printf("%s:%d -> %s:%d\n", srcIp.c_str(), srcPort, dstIp.c_str(), dstPort);
  cout << "filename: " << filename << endl;
  cout << "sentPacketCount : " << sentPacketCount << endl;
  cout << "recvPacketCount : " << recvPacketCount << endl;
  cout << "sentBytesCount  : " << sentBytesCount << endl;
  cout << "ackCount        : " << ackCount << endl;
  if (GlobOpts::withRecv) {
    cout << "recvPacketCount : " << recvPacketCount << endl;
    cout << "recvBytesCount  : " << recvBytesCount << endl;
    cout << "packets lost    : " << (sentPacketCount - recvPacketCount) << endl;
    cout << "packetLoss      : " << ((float)(sentPacketCount - recvPacketCount) / sentPacketCount) * 100 <<  "\%" << endl;
  }
}

void Dump::printRDBStats(){
  map<string, Connection*>::iterator cIt, cItEnd;

  int rdb_sent = 0;
  int rdb_miss = 0;
  int rdb_hits = 0;
  int totBytesSent = 0;

  printf("NOT SAVE!\n");
  exit_with_file_and_linenum(1, __FILE__, __LINE__);

  for (cIt = conns.begin(); cIt != conns.end(); cIt++){

//	  cIt->second->addRDBStats(&rdb_sent, &rdb_miss, &rdb_hits, &totBytesSent);

//	  if (!GlobOpts::aggInfo) {
//		  printf("RDB bytes sent: %d (%f%%)\n", rdb_sent, ((double) rdb_sent)/totBytesSent * 100);
//		  printf("RDB byte  miss: %d (%f%%)\n", rdb_miss, ((double) rdb_miss)/(rdb_sent) * 100);
//		  printf("RDB byte  hits: %d (%f%%)\n", rdb_hits, ((double) rdb_hits)/(rdb_sent) * 100);
//		  rdb_sent = 0;
//		  rdb_miss = 0;
//		  rdb_hits = 0;
//	  }

	  if (GlobOpts::print_packets)
		  cIt->second->printPacketDetails();
  }

  if (GlobOpts::aggInfo) {
	  printf("RDB stats for %ld connections\n", conns.size());
	  printf("RDB bytes sent: %d (%f%% of total bytes sent)\n", rdb_sent, ((double) rdb_sent)/totBytesSent * 100);
	  printf("RDB byte  miss: %d (%f%% of rdb bytes)\n", rdb_miss, ((double) rdb_miss)/(rdb_sent) * 100);
	  printf("RDB byte  hits: %d (%f%% of rdb bytes)\n", rdb_hits, ((double) rdb_hits)/(rdb_sent) * 100);
  }
}


void Dump::genRFiles() {
 map<string, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->genRFiles();
  }

  /* Print aggregate statistics */
  ofstream dcDiff, retr1, retr2, retr3, retr4, retr5, retr6, all;
  stringstream r1fn, r2fn, r3fn, r4fn, r5fn, r6fn, allfn, dcdfn;;

  r1fn << GlobOpts::prefix << "-1retr-aggr.dat";
  r2fn << GlobOpts::prefix << "-2retr-aggr.dat";
  r3fn << GlobOpts::prefix << "-3retr-aggr.dat";
  r4fn << GlobOpts::prefix << "-4retr-aggr.dat";
  r5fn << GlobOpts::prefix << "-5retr-aggr.dat";
  r6fn << GlobOpts::prefix << "-6retr-aggr.dat";
  allfn << GlobOpts::prefix << "-all-aggr.dat";

  retr1.open((char*)((r1fn.str()).c_str()), ios::out);
  retr2.open((char*)((r2fn.str()).c_str()), ios::out);
  retr3.open((char*)((r3fn.str()).c_str()), ios::out);
  retr4.open((char*)((r4fn.str()).c_str()), ios::out);
  retr5.open((char*)((r5fn.str()).c_str()), ios::out);
  retr6.open((char*)((r6fn.str()).c_str()), ios::out);
  all.open((char*)((allfn.str()).c_str()), ios::out);

  vector<int>::iterator it, it_end;
  it = GlobStats::retr1.begin();
  it_end = GlobStats::retr1.end();
  for(; it != it_end; it++){
    retr1 << *it << endl;
  }

  it = GlobStats::retr2.begin();
  it_end = GlobStats::retr2.end();
  for(; it != it_end; it++){
    retr2 << *it << endl;
  }

  it = GlobStats::retr3.begin();
  it_end = GlobStats::retr3.end();
  for(; it != it_end; it++){
    retr3 << *it << endl;
  }

  it = GlobStats::retr4.begin();
  it_end = GlobStats::retr4.end();
  for(; it != it_end; it++){
    retr4 << *it << endl;
  }

  it = GlobStats::retr5.begin();
  it_end = GlobStats::retr5.end();
  for(; it != it_end; it++){
    retr5 << *it << endl;
  }

  it = GlobStats::retr6.begin();
  it_end = GlobStats::retr6.end();
  for(; it != it_end; it++){
    retr6 << *it << endl;
  }

  it = GlobStats::all.begin();
  it_end = GlobStats::all.end();
  for(; it != it_end; it++){
    all << *it << endl;
  }

  retr1.close();
  retr2.close();
  retr3.close();
  retr4.close();
  all.close();
}


void Dump::free_resources() {
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->second;
	}
}
