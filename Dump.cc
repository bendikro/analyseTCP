#include "Dump.h"
#include "analyseTCP.h"

int GlobStats::totNumBytes;
map<ConnectionMapKey*, string, ConnectionKeyComparator> connKeys;

/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string src_port, string dst_port, string fn ){
  srcIp = src_ip;
  dstIp = dst_ip;
  srcPort = string(src_port);
  dstPort = string(dst_port);
  filename = fn;
  sentPacketCount = 0;
  sentBytesCount = 0;
  recvPacketCount = 0;
  recvBytesCount = 0;
  ackCount = 0;
}

Dump::~Dump() {
	map<ConnectionMapKey*, string>::iterator it, it_end;
	it_end = connKeys.end();
	for (it = connKeys.begin(); it != it_end; it++) {
		delete it->first;
	}
}

bool isNumeric(const char* pszInput, int nNumberBase) {
	string base = "0123456789ABCDEF";
	string input = pszInput;
	return (input.find_first_not_of(base.substr(0, nNumberBase)) == string::npos);
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
	struct pcap_pkthdr header;
	const u_char *data;
	map<string, Connection*>::iterator it, it_end;

	pcap_t *fd = pcap_open_offline(filename.c_str(), errbuf);
	if ( fd == NULL ) {
		cerr << "pcap: Could not open file: " << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	/* Set up pcap filter to include only outgoing tcp
	   packets with correct ip and port numbers.
	*/

	/* TODO: Add options to crop dumpfiles from front or back with n
	   minutes */

	bool src_port_range = !isNumeric(srcPort.c_str(), 10);
	bool dst_port_range = !isNumeric(dstPort.c_str(), 10);

	struct bpf_program compFilter;
	stringstream filterExp;
	filterExp << "tcp && src host " << srcIp;
	if (!srcPort.empty()) {
		filterExp << " && src " << (src_port_range ? "portrange " : "port ") << srcPort;
	}
	if (!dstIp.empty())
		filterExp << " && dst host " << dstIp;
	if (!dstPort.empty())
		filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << dstPort;

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
		data = (const u_char *) pcap_next(fd, &header);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd, errMsg);
		} else {
			processSent(&header, data); /* Sniff packet */
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
	if (!dstPort.empty())
		filterExp << " && src " << (dst_port_range ? "portrange " : "port ") << dstPort;
	filterExp << " && dst host " << srcIp;
	if (!srcPort.empty())
		filterExp << " && dst " << (src_port_range ? "portrange " : "port ") << srcPort;

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
		data = (const u_char *) pcap_next(fd2, &header);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd2, errMsg);
		} else {
			processAcks(&header, data); /* Sniff packet */
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

	struct byteStats bs, bsAggregated, bsAggregatedMin, bsAggregatedMax;
	memset(&bsAggregated, 0, sizeof(struct byteStats));
	memset(&bsAggregatedMin, 0, sizeof(struct byteStats));
	memset(&bsAggregatedMax, 0, sizeof(struct byteStats));
	bsAggregatedMin.minLat = bsAggregatedMin.minLength = bsAggregatedMin.avgLat = bsAggregatedMin.maxLat = (numeric_limits<int>::max)();
	bsAggregatedMax.maxLength = (numeric_limits<int>::max)();

	csAggregated.rdb_byte_hits = 0;
	csAggregated.rdb_byte_misses = 0;
	csAggregated.rdb_bytes_sent = 0;

	// Print stats for each connection or aggregated
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addPacketStats(&cs);
		cIt->second->addPacketStats(&csAggregated);

		/* Initialize bs struct */
		memset(&bs, 0, sizeof(struct byteStats));
		cIt->second->genBytesLatencyStats(&bs);

		if (!(GlobOpts::aggOnly)) {
			printf("\nSTATS FOR CONN: %s:%u -> %s:%u\n", cIt->second->getSrcIp().c_str(), cIt->second->srcPort,
			       cIt->second->getDstIp().c_str(), cIt->second->dstPort);
			printPacketStats(&cs, &bs, false);
		}

		if (!(GlobOpts::aggOnly)) {
			cout << "\nBytewise latency - Conn: " <<  cIt->second->getConnKey() << endl;
			printBytesLatencyStats(&cs, &bs, false, NULL, NULL);
		}

		if (GlobOpts::aggregate) {
			bsAggregated.minLat += bs.minLat;
			bsAggregated.maxLat += bs.maxLat;
			bsAggregated.minLength += bs.minLength;
			bsAggregated.maxLength += bs.maxLength;
			bsAggregated.avgLat += bs.avgLat;
			bsAggregated.cumLat += bs.cumLat;
			bsAggregated.avgLength += bs.avgLength;
			bsAggregated.cumLength += bs.cumLength;
			bsAggregated.retrans[0] += bs.retrans[0];
			bsAggregated.retrans[1] += bs.retrans[1];
			bsAggregated.retrans[2] += bs.retrans[2];
			bsAggregated.maxRetrans += bs.maxRetrans;

			// Get min values
			if (bsAggregatedMin.minLat > bs.minLat && bs.minLat > 0)
				bsAggregatedMin.minLat = bs.minLat;
			if (bsAggregatedMin.maxLat > bs.maxLat && bs.maxLat > 0)
				bsAggregatedMin.maxLat = bs.maxLat;
			if (bsAggregatedMin.avgLat > bs.avgLat && bs.avgLat > 0) {
				bsAggregatedMin.avgLat = bs.avgLat;
			}

			// Get max values
			if (bsAggregatedMax.minLat < bs.minLat)
				bsAggregatedMax.minLat = bs.minLat;
			if (bsAggregatedMax.maxLat < bs.maxLat)
				bsAggregatedMax.maxLat = bs.maxLat;
			if (bsAggregatedMax.avgLat < bs.avgLat)
				bsAggregatedMax.avgLat = bs.avgLat;
		}

		if (bs.percentiles_lengths)
			delete bs.percentiles_lengths;
		if (bs.percentiles_latencies)
			delete bs.percentiles_latencies;
	}

	if (GlobOpts::aggregate) {
		if (csAggregated.nrPacketsSent) { /* To avoid division by 0 */
			bsAggregated.avgLat /= conns.size();
			bsAggregated.avgLength /= conns.size();
			csAggregated.duration /= conns.size();
			bsAggregated.maxRetrans /= conns.size();
			bsAggregated.minLength /= conns.size();
			bsAggregated.maxLength /= conns.size();
			bsAggregated.minLat /= conns.size();
			bsAggregated.maxLat /= conns.size();

			cout << "\n\nAggregate Statistics for " << conns.size() << " connections:" << endl;
			printPacketStats(&csAggregated, &bsAggregated, true);

			/* Print Aggregate bytewise latency */
			cout << "Bytewise (application layer) latency" << endl;
			printBytesLatencyStats(&csAggregated, &bsAggregated, true, &bsAggregatedMin, &bsAggregatedMax);
		}
	}
}

/* Generate statistics for each connection.
   update aggregate stats if requested */
void Dump::printPacketStats(struct connStats *cs, struct byteStats *bs, bool aggregated) {
	printf("Duration: %u seconds (%f hours)\n"			\
	       "Total packets sent                            : %10d\n"	\
	       "Total data packets sent                       : %10d\n"	\
	       "Total pure acks (no payload) (Incl. SYN/FIN)  : %10d\n"	\
	       "Number of retransmissions                     : %10d\n"	\
	       "Number of packets with bundled segments       : %10d\n"	\
	       "Total bytes sent (payload)                    : %10lu\n"	\
	       "Number of unique bytes                        : %10lu\n"	\
	       "Number of retransmitted bytes                 : %10d\n"	\
	       "Estimated loss rate based on retransmissions  : %10.2f %%\n",
	       cs->duration, ((double) cs->duration / 60 / 60),
	       cs->nrPacketsSent, cs->nrDataPacketsSent, cs->nrPacketsSent - cs->nrDataPacketsSent, cs->nrRetrans, cs->bundleCount, cs->totBytesSent,
	       cs->totUniqueBytes, cs->totRetransBytesSent,
	       (((double) cs->nrRetrans / cs->nrPacketsSent) * 100));

	if (GlobOpts::incTrace) {
		printf("Number of redundant bytes                     : %10lu\n"	\
		       "Redundancy                                    : %10.2f %%\n",
		       cs->redundantBytes, ((double) cs->redundantBytes / cs->totUniqueBytes) * 100);
	} else {
		printf("Redundancy                                    : %10.2f %%\n",
		       ((double) (cs->totBytesSent - cs->totUniqueBytes) / cs->totBytesSent) * 100);
	}

	printf("\nPayload size stats:\n");

	if (aggregated) {
		printf("  Average of all packets in all connections   : %10d\n",
		       (int) floorf((double) (cs->totBytesSent / cs->nrDataPacketsSent)));
		printf("  Average of the average for each connection  : %10lld\n", bs->avgLength);
	}
	else {
		printf("  Average                                     : %10lld\n", bs->avgLength);
	}

	if (bs != NULL) {
		if (aggregated) {
			printf("  Minimum (average for all connections)       : %10lld\n" \
			       "  Maximum (average for all connections)       : %10lld\n",
			       bs->minLength, bs->maxLength);
		}
		else {
			printf("  Minimum                                     : %10lld\n" \
			       "  Maximum                                     : %10lld\n",
			       bs->minLength, bs->maxLength);
		}

		if (bs->percentiles_lengths) {
			printf("  Standard deviation                          : %f\n" \
			       "  First percentile                            : %f\n"\
			       "  First  quartile (25th percentile)           : %f\n" \
			       "  Second quartile (50th percentile) (median)  : %f\n" \
			       "  Third  quartile (75th percentile)           : %f\n"\
			       "  Ninety ninth percentile                     : %f\n",
			       bs->stdevLength,
			       bs->percentiles_lengths->first_percentile,
			       bs->percentiles_lengths->first_quartile,
			       bs->percentiles_lengths->second_quartile,
			       bs->percentiles_lengths->third_quartile,
			       bs->percentiles_lengths->ninetynine_percentile);
		}
	}

	if (cs->rdb_bytes_sent) {
		printf("\nRDB stats:\n");
		printf("  RDB packets                                 : %10d (%.2f%% of data packets sent)\n", cs->bundleCount, ((double) cs->bundleCount) / cs->nrDataPacketsSent * 100);
		printf("  RDB bytes bundled                           : %10lu (%.2f%% of total bytes sent)\n", cs->rdb_bytes_sent, ((double) cs->rdb_bytes_sent) / cs->totBytesSent * 100);

		if (cs->rdb_stats_available) {
			printf("  RDB packet hits                             : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_hits, ((double) cs->rdb_packet_hits) / cs->bundleCount * 100);
			printf("  RDB packet misses                           : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_misses, ((double) cs->rdb_packet_misses) / cs->bundleCount * 100);
			printf("  RDB byte   hits                             : %10lu (%.2f%% of RDB bytes)\n", cs->rdb_byte_hits, ((double) cs->rdb_byte_hits / cs->rdb_bytes_sent) * 100);
			printf("  RDB byte   misses                           : %10lu (%.2f%% of RDB bytes)\n", cs->rdb_byte_misses, ((double) cs->rdb_byte_misses / cs->rdb_bytes_sent) * 100);
		}
	}
	cout << "--------------------------------------------------" << endl;
}


/* Generate statistics for bytewise latency */
void Dump::printBytesLatencyStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax) {
	printf("\nLatency stats");

	if (aggregated) {
		printf(" (Average for all the connections)\n");
	}
	else
		printf(":\n");

	if (aggregated) {
		printf("  Average latencies (min/avg/max)             :    %7d, %7lld, %7d ms\n", bs->minLat, bs->avgLat, bs->maxLat);
		printf("  Minimum latencies (min/avg/max)             :    %7d, %7lld, %7d ms\n", aggregatedMin->minLat, aggregatedMin->avgLat, aggregatedMin->maxLat);
		printf("  Maximum latencies (min/avg/max)             :    %7d, %7lld, %7d ms\n", aggregatedMax->minLat, aggregatedMax->avgLat, aggregatedMax->maxLat);
		printf("  Average for all packets in all all conns    : %10lld ms\n", bs->cumLat / cs->nrPacketsSent);
	}
	else {
		printf("  Minimum latency                             : %7d ms\n", bs->minLat);
		printf("  Maximum latency                             : %7d ms\n", bs->maxLat);
		printf("  Average of all packets                      : %7lld ms\n", bs->avgLat);
	}

	if (bs->stdevLat) {
		cout << "  Standard deviation                          : " << bs->stdevLat << " ms" << endl;
	}
	if (bs->percentiles_latencies) {
		cout << "  First percentile                            : " << bs->percentiles_latencies->first_percentile << endl;
		cout << "  First  quartile  (25th percentile)          : " << bs->percentiles_latencies->first_quartile << endl;
		cout << "  Second quartile  (50th percentile) (median) : " << bs->percentiles_latencies->second_quartile << endl;
		cout << "  Third  quartile  (75th percentile)          : " << bs->percentiles_latencies->third_quartile << endl;
		cout << "  Ninety ninth percentile                     : " << bs->percentiles_latencies->ninetynine_percentile << endl;
	}
	cout << "--------------------------------------------------" << endl;

	for (int i = 0; i < MAX_STAT_RETRANS; i++) {
		cout << "Occurrences of " << (i +1) << ". retransmission              : " << bs->retrans[i] << endl;
	}
	cout << "Max retransmissions                           : " << bs->maxRetrans << endl;
	cout << "==================================================" << endl;
}

void Dump::getTCPTimeStamp(struct DataSeg* data, uint8_t* opts, int option_length) {

	typedef struct {
		uint8_t kind;
		uint8_t size;
	} tcp_option_t;
	int offset = 0;

	while (*opts != 0 && offset < option_length) {
		tcp_option_t* _opt = (tcp_option_t*) (opts + offset);
		if (_opt->kind == 1 /* NOP */) {
			offset += 1;
			continue;
		}
		if (_opt->kind == 8 /* Timestamp */) {
			data->tstamp_tcp = ntohl(*(((uint32_t*) (opts + offset + 2))));
			break;
		}
		if (_opt->size == 0) {
			assert(0 && "opt->size is null!\n");
			break;
		}
		offset += _opt->size;
	}
}


/* Process outgoing packets */
void Dump::processSent(const struct pcap_pkthdr* header, const u_char *data) {
	//static const struct sniff_ethernet *ethernet; /* The ethernet header */
	static const struct sniff_ip *ip; /* The IP header */
	static const struct sniff_tcp *tcp; /* The TCP header */
	static Connection *tmpConn;
	static u_int ipSize;
	static u_int ipHdrLen;
	static u_int tcpHdrLen;
	static string connKey;
	static struct sendData sd;

	/* Finds the different headers+payload */
	//ethernet = (struct sniff_ethernet*) data;
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
	sd.tcpOptionLen = tcpHdrLen - 20;
	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.data.tstamp_pcap  = header->ts;
	sd.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq     = get_relative_sequence_number(sd.seq_absolute, tmpConn->firstSeq, tmpConn->lastLargestEndSeq, tmpConn->lastLargestSeqAbsolute);
	sd.data.endSeq  = sd.data.seq + sd.data.payloadSize;
	sd.data.retrans = false;
	sd.data.is_rdb  = false;
	sd.data.rdb_end_seq = 0;

	if (sd.data.payloadSize > 0) {
		sd.data.endSeq -= 1;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	getTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);

	sentPacketCount++;
	sentBytesCount += sd.data.payloadSize;

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
uint64_t Dump::get_relative_sequence_number(uint32_t seq, uint32_t firstSeq, ulong largestSeq, uint32_t largestSeqAbsolute) {
	static ulong wrap_index;
	static uint64_t seq_relative;
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

	wrap_index /= 4294967296L;

	// When seq has wrapped, wrap_index will make sure the relative sequence number continues to grow
	seq_relative = seq + (wrap_index * 4294967296L) - firstSeq;
	if (seq_relative > 9999999999) {
		assert(0 && "Incorrect sequence number calculation!\n");
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
    cerr << "srcIp: " << srcIp << endl;
    cerr << "tmpSrcIp: " << tmpSrcIp << endl;
  }

  if (!GlobOpts::recvNatIP.empty()) {
    cerr << "receiver side NATing handled" << endl;
    tmpDstIp = GlobOpts::recvNatIP;
    cerr << "dstIp: " << dstIp << endl;
    cerr << "tmpDstIp: " << tmpDstIp << endl;
  }

  pcap_t *fd = pcap_open_offline(recvFn.c_str(), errbuf);
  if ( fd == NULL ) {
	  cerr << "pcap: Could not open file: " << recvFn << endl;
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  /* Set up pcap filter to include only incoming tcp
     packets with correct IP and port numbers.
     We exclude packets with no TCP payload. */
  struct bpf_program compFilter;
  stringstream filterExp;

  bool src_port_range = !isNumeric(srcPort.c_str(), 10);
  bool dst_port_range = !isNumeric(dstPort.c_str(), 10);

  filterExp.str("");
  filterExp << "tcp";
  if (!tmpSrcIp.empty())
	  filterExp << " && src host " << tmpSrcIp;
  if (!tmpDstIp.empty())
	  filterExp << " && dst host " << tmpDstIp;
  if (!srcPort.empty())
	  filterExp << " && src " << (src_port_range ? "portrange " : "port ") << srcPort;
  if (!dstPort.empty())
	  filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << dstPort;

  //filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";

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

  if ((GlobOpts::print_packets || GlobOpts::rdbDetails)) {
	  calculateRetransAndRDBStats();
  }

  if (GlobOpts::withCDF) {
	  makeCDF();

	  if ((GlobOpts::withCDF))
		  printCDF();

	  /* Calculate clock drift for all eligible connections
		 eligible: more than 500 ranges &&
		 more than 2 minutes duration
		 make drift compensated CDF*/
	  makeDcCdf();

	  if ((GlobOpts::aggOnly))
		  printDcCdf();

	  if (GlobOpts::aggregate){
		  printAggCdf();
		  printAggDcCdf();
	  }
  }
}

/* Process packets */
void Dump::processRecvd(const struct pcap_pkthdr* header, const u_char *data) {
	//const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  static Connection *tmpConn;

    /* Finds the different headers+payload */
//  ethernet = (struct sniff_ethernet*)(data);
  ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
  u_int ipSize = ntohs(ip->ip_len);
  u_int ipHdrLen = IP_HL(ip)*4;
  tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
  u_int tcpHdrLen = TH_OFF(tcp)*4;

  string connKey = getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport);

  /* It should not be possible that the connection is not yet created */
  /* If lingering ack arrives for a closed connection, this may happen */
  if (conns.count(connKey) == 0) {
	  cerr << "Connection found in recveiver dump that does not exist in sender: " << connKey << ". Maybe NAT is in effect?  Exiting." << endl;
	  exit_with_file_and_linenum(1, __FILE__, __LINE__);
  }

  tmpConn = conns[connKey];

  /* Prepare packet data struct */
  struct sendData sd;
  sd.totalSize        = header->len;
  sd.ipSize           = ipSize;
  sd.ipHdrLen         = ipHdrLen;
  sd.tcpHdrLen        = tcpHdrLen;
  sd.tcpOptionLen     = tcpHdrLen - 20;
  sd.data.payloadSize = ipSize - (ipHdrLen + tcpHdrLen);
  sd.seq_absolute     = ntohl(tcp->th_seq);
  sd.data.seq         = get_relative_sequence_number(sd.seq_absolute, tmpConn->firstSeq, tmpConn->lastLargestRecvEndSeq, tmpConn->lastLargestRecvSeqAbsolute);
  sd.data.endSeq      = sd.data.seq + sd.data.payloadSize;
  sd.data.tstamp_pcap = header->ts;
  sd.data.is_rdb = false;
  sd.data.rdb_end_seq = 0;
  sd.data.retrans = 0;

  if (sd.data.seq == ULONG_MAX) {
	  if (tmpConn->lastLargestRecvEndSeq == 0) {
		  printf("Found invalid sequence numbers in beginning of receive dump. Probably the sender tcpdump didn't start in time to save this packets\n");
	  }
	  else {
		  printf("Found invalid sequence number in received data!: %lu -> %lu\n", sd.seq_absolute, sd.data.seq);
	  }
	  return;
  }

  uint8_t* opt = (uint8_t*) tcp + 20;
  getTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

  /* define/compute tcp payload (segment) offset */
  sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);
  recvPacketCount++;
  recvBytesCount += sd.data.payloadSize;
  tmpConn->registerRecvd(&sd);
}

void Dump::calculateRetransAndRDBStats() {
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->rm->calculateRetransAndRDBStats();
	}
}

void Dump::write_loss_to_file() {
	FILE *loss_file;
	stringstream lossfn;
	lossfn << GlobOpts::prefix << "loss" << ".dat";
	loss_file = fopen(lossfn.str().c_str(), "w");

	if (loss_file == NULL) {
		printf("Failed to open loss file for writing '%s'\n", lossfn.str().c_str());
		return;
	}

	uint32_t timeslice_count = 0;

	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		timeslice_count = std::max(timeslice_count, cIt->second->rm->getDuration());
	}

	unsigned timeslice = 1;

	timeslice_count /= timeslice;

	for (unsigned i = 0; i < timeslice_count; i++) {
		fprintf(loss_file, "%10u", i);
	}
	fprintf(loss_file, "\n");

	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->rm->write_loss_over_time(timeslice, timeslice_count, loss_file);
	}
	fclose(loss_file);
}

void Dump::makeCDF() {
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->makeCDF();
	}
}

void Dump::printCDF(){
	ofstream cdf_f;
	stringstream cdffn;
	cdffn << GlobOpts::prefix << "cdf.dat";
	cdf_f.open((char*)((cdffn.str()).c_str()), ios::out);

	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->printCDF(&cdf_f);
	}
	cdf_f.close();
}

void Dump::printDcCdf(){
	ofstream dccdf_f;
	stringstream dccdffn;
	dccdffn << GlobOpts::prefix << "dccdf.dat";
	dccdf_f.open((char*)((dccdffn.str()).c_str()), ios::out);

	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->printDcCdf(&dccdf_f);
	}
	dccdf_f.close();
}

void Dump::printAggCdf(){
	char print_buf[300];
	ofstream stream;
	stringstream filename;
	filename << GlobOpts::prefix << "agg-cdf.dat";
	stream.open((char*)((filename.str()).c_str()), ios::out);

	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = GlobStats::cdf.begin();
	nit_end = GlobStats::cdf.end();

	stream << endl << endl << "#Aggregated CDF:" << endl;
	stream << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
		sprintf(print_buf, "time: %10d    CDF: %.10f\n", (*nit).first, cdfSum);
		stream << print_buf;
	}
}

void Dump::printAggDcCdf(){
	char print_buf[300];
	ofstream stream;
	stringstream filename;
	filename << GlobOpts::prefix << "agg-dccdf.dat";
	stream.open((char*)((filename.str()).c_str()), ios::out);

	map<const int, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = GlobStats::dcCdf.begin();
	nit_end = GlobStats::dcCdf.end();

	stream << endl << "#Aggregated, drift-compensated CDF:" << endl;
	stream << "#------ Average drift : " << GlobStats::avgDrift << "ms/s ------" << endl;
	stream << "#Relative delay      Percentage" << endl;
	for (; nit != nit_end; nit++) {
		cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
		sprintf(print_buf, "time: %10d    CDF: %.10f\n", (*nit).first, cdfSum);
		stream << print_buf;
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
  printf("%s:%s -> %s:%s\n", srcIp.c_str(), srcPort.c_str(), dstIp.c_str(), dstPort.c_str());
  cout << "Filename: " << filename << endl;
  cout << "Sent Packet Count     : " << sentPacketCount << endl;
  cout << "Received Packet Count : " << recvPacketCount << endl;
  cout << "Sent Bytes Count      : " << sentBytesCount << endl;
  cout << "ACK Count             : " << ackCount << endl;
  if (GlobOpts::withRecv) {
	  map<string, Connection*>::iterator cIt, cItEnd;
	  long int ranges_count = 0;
	  long int ranges_lost = 0;
	  for (cIt = conns.begin(); cIt != conns.end(); cIt++){
		  ranges_count += cIt->second->rm->getByteRangesCount();
		  ranges_lost += cIt->second->rm->getByteRangesLost();
	  }

    cout << "Received Bytes Count  : " << recvBytesCount << endl;
    cout << "Packets lost          : " << (sentPacketCount - recvPacketCount) << endl;
    cout << "Packet  Loss          : " << ((double) (sentPacketCount - recvPacketCount) / sentPacketCount) * 100 <<  "\%" << endl;

    cout << "Ranges received       : " << (ranges_count) << endl;
    cout << "Ranges lost           : " << (ranges_lost) << endl;
    cout << "Ranges Loss           : " << ((double) (ranges_lost) / ranges_count) * 100 <<  "\%" << endl;
  }
}

void Dump::genRFiles() {
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->genRFiles();
	}

	stringstream filename_tmp;
	vector<ofstream*> streams;

	vector<string> filenames;
	filenames.push_back(string("1retr-aggr.dat"));
	filenames.push_back(string("2retr-aggr.dat"));
	filenames.push_back(string("3retr-aggr.dat"));
	filenames.push_back(string("4retr-aggr.dat"));
	filenames.push_back(string("5retr-aggr.dat"));
	filenames.push_back(string("6retr-aggr.dat"));
	filenames.push_back(string("all-aggr.dat"));
	filenames.push_back(string("all-durations.dat"));

	vector<vector <int> > vectors;
	vectors.push_back(GlobStats::retr1);
	vectors.push_back(GlobStats::retr2);
	vectors.push_back(GlobStats::retr3);
	vectors.push_back(GlobStats::retr4);
	vectors.push_back(GlobStats::retr5);
	vectors.push_back(GlobStats::retr6);
	vectors.push_back(GlobStats::all);

	for (unsigned long int i = 0; i < filenames.size(); i++) {
		filename_tmp.str("");
		filename_tmp << GlobOpts::prefix << filenames[i];
		streams.push_back(new ofstream(filename_tmp.str().c_str(), ios::out));
	}

	vector<int>::iterator it, it_end;
	unsigned long int i;
	for (i = 0; i < vectors.size(); i++) {
		it = vectors[i].begin();
		it_end = vectors[i].end();
		for (; it != it_end; it++){
			*streams[i] << *it << endl;
		}
	}

	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		*streams[i] << cIt->second->rm->getDuration() << endl;
	}
	i++;

	for (unsigned long int i = 0; i < filenames.size(); i++) {
		streams[i]->close();
		delete streams[i];
	}
}

void Dump::free_resources() {
	map<string, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->second;
	}
}
