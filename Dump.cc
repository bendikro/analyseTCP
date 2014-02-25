#include "Dump.h"
#include "analyseTCP.h"
#include "color_print.h"

extern GlobStats *globStats;
int GlobStats::totNumBytes;

/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string src_port, string dst_port, string fn) {
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
	max_payload_size = 0;
}

/*
  Checks if a char buf is a string
*/
bool isNumeric(const char* pszInput, int nNumberBase) {
	string base = "0123456789ABCDEF";
	string input = pszInput;
	return (input.find_first_not_of(base.substr(0, nNumberBase)) == string::npos);
}

string getConnKey(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort) {
	static char src_ip_buf[INET_ADDRSTRLEN];
	static char dst_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, srcIp, src_ip_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dstIp, dst_ip_buf, INET_ADDRSTRLEN);
	stringstream connKeyTmp;
	connKeyTmp << src_ip_buf << "-" << ntohs(*srcPort) << "-" << dst_ip_buf << "-" << ntohs(*dstPort);
	return connKeyTmp.str();
}

Connection* Dump::getConn(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort, const uint32_t *seq) {
	static struct ConnectionMapKey connKey;
	map<ConnectionMapKey*, Connection*>::iterator it;
	static char src_ip_buf[INET_ADDRSTRLEN];
	static char dst_ip_buf[INET_ADDRSTRLEN];
	memcpy(&connKey.ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKey.ip_dst, dstIp, sizeof(struct in_addr));
	connKey.src_port = *srcPort;
	connKey.dst_port = *dstPort;

	it = conns.find(&connKey);
	// Returning the existing connection key
	if (it != conns.end()) {
		return it->second;
	}

	if (seq == NULL) {
		return NULL;
	}

	inet_ntop(AF_INET, srcIp, src_ip_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dstIp, dst_ip_buf, INET_ADDRSTRLEN);

	Connection *tmpConn = new Connection(*srcIp, ntohs(*srcPort), *dstIp,
										 ntohs(*dstPort), ntohl(*seq));
	ConnectionMapKey *connKeyToInsert = new ConnectionMapKey();
	memcpy(&connKeyToInsert->ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKeyToInsert->ip_dst, dstIp, sizeof(struct in_addr));
	connKeyToInsert->src_port = connKey.src_port;
	connKeyToInsert->dst_port = connKey.dst_port;
	conns.insert(pair<ConnectionMapKey*, Connection*>(connKeyToInsert, tmpConn));
	return tmpConn;
}


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender() {
	int packetCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *data;
	map<ConnectionMapKey*, Connection*>::iterator it, it_end;

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

	filterExp << "tcp";
	if (!srcIp.empty())
		filterExp << " && src host " << srcIp;
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
	pcap_freecode(&compFilter);

	colored_printf(YELLOW, "Processing sent packets...\n");
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
	} while (data != NULL);

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

	if (!srcIp.empty())
		filterExp << " && dst host " << srcIp;
	if (!srcPort.empty())
		filterExp << " && dst " << (src_port_range ? "portrange " : "port ") << srcPort;

/*
  filterExp << " && ((tcp[tcpflags] & tcp-syn) != tcp-syn)"
  << " && ((tcp[tcpflags] & tcp-fin) != tcp-fin)"
  << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";
*/

	filterExp << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";

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
	pcap_freecode(&compFilter);

	colored_printf(YELLOW, "Processing acknowledgements...\n");

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

	struct byteStats bsAggregated, bsAggregatedMin, bsAggregatedMax;
	bsAggregatedMin.minLat = bsAggregatedMin.minLength = bsAggregatedMin.avgLat = bsAggregatedMin.maxLat = (numeric_limits<int>::max)();
	bsAggregatedMax.maxLength = (numeric_limits<int>::max)();

	csAggregated.rdb_byte_hits = 0;
	csAggregated.rdb_byte_misses = 0;
	csAggregated.rdb_bytes_sent = 0;

	// Print stats for each connection or aggregated
	map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> sortedConns;
	fillWithSortedConns(sortedConns);
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = sortedConns.begin(); cIt != sortedConns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addPacketStats(&cs);
		cIt->second->addPacketStats(&csAggregated);

		/* Initialize bs struct */
		struct byteStats bs;

		if (!(GlobOpts::aggOnly)) {
			bs.percentiles_lengths.init();
			bs.percentiles_latencies.init();
		}

		cIt->second->genBytesLatencyStats(&bs);

		if (!(GlobOpts::aggOnly)) {
			colored_printf(YELLOW, "STATS FOR CONN: %s:%u -> %s:%u", cIt->second->getSrcIp().c_str(), cIt->second->srcPort,
			       cIt->second->getDstIp().c_str(), cIt->second->dstPort);

			if (GlobOpts::analyse_start || GlobOpts::analyse_end || GlobOpts::analyse_duration) {
				colored_printf(YELLOW, " (Interval alalysed (sec): %d-%d)", cIt->second->rm->analyse_time_sec_start, cIt->second->rm->analyse_time_sec_end);
			}
			printf("\n");
			printPacketStats(&cs, &bs, false);
		}

		if (!(GlobOpts::aggOnly)) {
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

			// Add retrans stats
			if ((ulong) bs.retrans.size() > bsAggregated.retrans.size()) {
				for (ulong i = bsAggregated.retrans.size(); i < bs.retrans.size(); i++) {
					bsAggregated.retrans.push_back(0);
				}
			}

			for (ulong i = 0; i < bs.retrans.size(); i++) {
				bsAggregated.retrans[i] += bs.retrans[i];
			}

			// Add dupack stats
			if ((ulong) bs.dupacks.size() > bsAggregated.dupacks.size()) {
				for (ulong i = bsAggregated.dupacks.size(); i < bs.dupacks.size(); i++) {
					bsAggregated.dupacks.push_back(0);
				}
			}

			for (ulong i = 0; i < bs.dupacks.size(); i++) {
				bsAggregated.dupacks[i] += bs.dupacks[i];
			}

			// Get minimum values
			if (bsAggregatedMin.minLat > bs.minLat && bs.minLat > 0)
				bsAggregatedMin.minLat = bs.minLat;
			if (bsAggregatedMin.maxLat > bs.maxLat && bs.maxLat > 0)
				bsAggregatedMin.maxLat = bs.maxLat;
			if (bsAggregatedMin.avgLat > bs.avgLat && bs.avgLat > 0) {
				bsAggregatedMin.avgLat = bs.avgLat;
			}

			// Get maximum values
			if (bsAggregatedMax.minLat < bs.minLat)
				bsAggregatedMax.minLat = bs.minLat;
			if (bsAggregatedMax.maxLat < bs.maxLat)
				bsAggregatedMax.maxLat = bs.maxLat;
			if (bsAggregatedMax.avgLat < bs.avgLat)
				bsAggregatedMax.avgLat = bs.avgLat;

			// Add the latency and payload values
			bsAggregated.latencies.insert(bsAggregated.latencies.end(), bs.latencies.begin(), bs.latencies.end());
			bsAggregated.payload_lengths.insert(bsAggregated.payload_lengths.end(), bs.payload_lengths.begin(), bs.payload_lengths.end());
		}
	}

	if (GlobOpts::aggregate) {
		if (csAggregated.nrPacketsSent) { /* To avoid division by 0 */
			bsAggregated.avgLat /= sortedConns.size();
			bsAggregated.avgLength /= sortedConns.size();
			csAggregated.duration /= sortedConns.size();
			bsAggregated.minLength /= sortedConns.size();
			bsAggregated.maxLength /= sortedConns.size();
			bsAggregated.minLat /= sortedConns.size();
			bsAggregated.maxLat /= sortedConns.size();
			bsAggregated.percentiles_lengths.init();
			bsAggregated.percentiles_latencies.init();

			std::sort(bsAggregated.latencies.begin(), bsAggregated.latencies.end());
			percentiles(&bsAggregated.latencies, &bsAggregated.percentiles_latencies);
			std::sort(bsAggregated.payload_lengths.begin(), bsAggregated.payload_lengths.end());
			percentiles(&bsAggregated.payload_lengths, &bsAggregated.percentiles_lengths);

			cout << "\nAggregated Statistics for " << sortedConns.size() << " connections:" << endl;
			printPacketStats(&csAggregated, &bsAggregated, true);

			/* Print Aggregate bytewise latency */
			printBytesLatencyStats(&csAggregated, &bsAggregated, true, &bsAggregatedMin, &bsAggregatedMax);
		}
	}
}

void print_stats_separator(bool final) {
	if (final)
		cout << "===============================================================" << endl << endl;
	else
		cout << "---------------------------------------------------------------" << endl;
}

/* Generate statistics for each connection.
   update aggregate stats if requested */
void Dump::printPacketStats(struct connStats *cs, struct byteStats *bs, bool aggregated) {
	printf("  Duration: %u seconds (%f hours)\n", cs->duration, ((double) cs->duration / 60 / 60));

	if (cs->nrPacketsSent != cs->nrPacketsSentFoundInDump) {
		printf("  Total packets sent (adj. for fragmentation)   : %10d\n", cs->nrPacketsSent);
		printf("  Total packets sent (found in dump)            : %10d\n", cs->nrPacketsSentFoundInDump);
		printf("  Total data packets sent (adj.)                : %10d\n", cs->nrDataPacketsSent);
		printf("  Total data packets sent (found)               : %10d\n", cs->nrDataPacketsSent- (cs->nrPacketsSent - cs->nrPacketsSentFoundInDump));
	}
	else {
		printf("  Total packets sent                            : %10d\n", cs->nrPacketsSent);
		printf("  Total data packets sent                       : %10d\n", cs->nrDataPacketsSent);
	}
	char syn_fin_rst[30];
	sprintf(syn_fin_rst, "%d/%d/%d", cs->synCount, cs->finCount, cs->rstCount);

	printf("  Total pure acks (no payload)                  : %10d\n"	\
	       "  SYN/FIN/RST packets sent                      : %10s\n"	\
	       "  Number of retransmissions                     : %10d\n"	\
	       "  Number of packets with bundled segments       : %10d\n"	\
		   "  Number of received acks                       : %10d\n"    \
	       "  Total bytes sent (payload)                    : %10lu\n"	\
	       "  Number of unique bytes                        : %10lu\n"	\
	       "  Number of retransmitted bytes                 : %10d\n"	\
		   "  Redundant bytes (bytes already sent)          : %10lu (%.2f %%)\n",
		   cs->pureAcksCount, syn_fin_rst,
		   cs->nrRetrans, cs->bundleCount, cs->ackCount, cs->totBytesSent,
	       cs->totUniqueBytes, cs->totRetransBytesSent, cs->totBytesSent - cs->totUniqueBytes,
	       ((double) (cs->totBytesSent - cs->totUniqueBytes) / cs->totBytesSent) * 100);

	if (cs->nrPacketsSent != cs->nrPacketsSentFoundInDump) {
		printf("  Estimated loss rate based on retransmission\n");
		printf("    Based on sent pkts (adj. for fragmentation) : %10.2f %%\n",
			   (((double) cs->nrRetrans / cs->nrPacketsSent) * 100));
		printf("    Based on sent pkts (found in dump)          : %10.2f %%\n",
			   (((double) cs->nrRetrans / cs->nrPacketsSentFoundInDump) * 100));

	}
	else {
		printf("  Estimated loss rate based on retransmissions  : %10.2f %%\n",
			   (((double) cs->nrRetrans / cs->nrPacketsSent) * 100));
	}

	if (GlobOpts::withRecv && cs->ranges_sent) {
		print_stats_separator(false);
		printf("Receiver side loss stats:\n");
		printf("  Bytes Lost (actual loss on receiver side)     : %10lu\n", cs->bytes_lost);
		printf("  Bytes Loss                                    : %10.2f %%\n", ((double) (cs->bytes_lost) / cs->totBytesSent) * 100);
		printf("  Ranges Lost (actual loss on receiver side)    : %10lu\n", cs->ranges_lost);
		printf("  Ranges Loss                                   : %10.2f %%\n", ((double) (cs->ranges_lost) / cs->ranges_sent) * 100);
	}

	print_stats_separator(false);
	printf("Payload size stats:\n");

	if (aggregated) {
		printf("  Average of all packets in all connections     : %10d\n",
		       (int) floorf((double) (cs->totBytesSent / cs->nrDataPacketsSent)));
		printf("  Average of the average for each connection    : %10lld\n", bs->avgLength);
	}
	else {
		printf("  Average                                       : %10lld\n", bs->avgLength);
	}

	if (bs != NULL) {
		if (aggregated) {
			printf("  Minimum (average for all connections)         : %10lld\n" \
			       "  Maximum (average for all connections)         : %10lld\n",
			       bs->minLength, bs->maxLength);
		}
		else {
			printf("  Minimum                                       : %10lld\n" \
			       "  Maximum                                       : %10lld\n",
			       bs->minLength, bs->maxLength);
		}

		if (bs->percentiles_lengths.percentiles.size()) {
			bs->percentiles_lengths.print("  %*sth percentile %-26s    : %10.0f\n", true);
		}
	}

	if (cs->rdb_bytes_sent) {
		print_stats_separator(false);
		printf("RDB stats:\n");
		printf("  RDB packets                                   : %10d (%.2f%% of data packets sent)\n", cs->bundleCount, ((double) cs->bundleCount) / cs->nrDataPacketsSent * 100);
		printf("  RDB bytes bundled                             : %10lu (%.2f%% of total bytes sent)\n", cs->rdb_bytes_sent, ((double) cs->rdb_bytes_sent) / cs->totBytesSent * 100);

		if (GlobOpts::withRecv) {
			printf("  RDB packet hits                               : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_hits, ((double) cs->rdb_packet_hits) / cs->bundleCount * 100);
			printf("  RDB packet misses                             : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_misses, ((double) cs->rdb_packet_misses) / cs->bundleCount * 100);
			printf("  RDB byte hits                                 : %10lu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   cs->rdb_byte_hits, ((double) cs->rdb_byte_hits / cs->rdb_bytes_sent) * 100, ((double) cs->rdb_byte_hits / cs->totBytesSent) * 100);
			printf("  RDB byte misses                               : %10lu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   cs->rdb_byte_misses, ((double) cs->rdb_byte_misses / cs->rdb_bytes_sent) * 100, ((double) cs->rdb_byte_misses / cs->totBytesSent) * 100);
		}
	}
	print_stats_separator(false);
}


/* Generate statistics for bytewise latency */
void Dump::printBytesLatencyStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax) {
	printf("Latency stats");

	if (aggregated) {
		printf(" (Average for all the connections)\n");
	}
	else
		printf(":\n");

	if (aggregated) {
		printf("  Minimum latencies (min, avg, max)             :    %7d, %7d, %7d ms\n", aggregatedMin->minLat, bs->minLat, aggregatedMax->minLat);
		printf("  Average latencies (min, avg, max)             :    %7lld, %7lld, %7lld ms\n", aggregatedMin->avgLat, bs->avgLat, aggregatedMax->avgLat);
		printf("  Maximum latencies (min, avg, max)             :    %7d, %7d, %7d ms\n", aggregatedMin->maxLat, bs->maxLat, aggregatedMax->maxLat);
		printf("  Average for all packets in all all conns      : %10lld ms\n", bs->cumLat / cs->nrPacketsSent);

	}
	else {
		printf("  Minimum                                       : %7d ms\n", bs->minLat);
		printf("  Average                                       : %7lld ms\n", bs->avgLat);
		printf("  Maximum                                       : %7d ms\n", bs->maxLat);
	}

	if (bs->percentiles_latencies.percentiles.size()) {
		bs->percentiles_latencies.print("  %*sth percentile %-26s    : %10.0f\n", true);
	}

	if (GlobOpts::verbose) {
		vector<int> retrans_accumed = bs->retrans;
		for (ulong i = retrans_accumed.size() - 1; i > 0; i--) {
			retrans_accumed[i-1] += retrans_accumed[i];
		}

		print_stats_separator(false);
		printf("  Max retransmissions                           : %10lu \n", bs->retrans.size());
		for (ulong i = 0; i < bs->retrans.size(); i++) {
			if ((GlobOpts::verbose < 2) && i > 2)
				break;
			if (bs->retrans[i] == 0)
				break;
			printf("  %2lu. retransmission (count / accumulated)      : %6d / %d\n", i+1, bs->retrans[i], retrans_accumed[i]);
		}
		print_stats_separator(false);

		vector<int> dupacks_accumed = bs->dupacks;
		for (ulong i = dupacks_accumed.size() - 1; i > 0; i--) {
			dupacks_accumed[i-1] += dupacks_accumed[i];
		}
		printf("  Max dupacks                                   : %10lu \n", bs->dupacks.size());
		for (ulong i = 0; i < bs->dupacks.size(); i++) {
			if ((GlobOpts::verbose > 1) || i < 3)
				printf("  %2lu. dupacks (count / accumulated)             : %6d / %d\n", i+1, bs->dupacks[i], dupacks_accumed[i]);
			//printf("  Occurrences of %2lu. dupacks                   : %d\n", i + 1, bs->dupacks[i]);
		}
	}
	print_stats_separator(true);
}

void Dump::findTCPTimeStamp(struct DataSeg* data, uint8_t* opts, int option_length) {

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
			data->tstamp_tcp_echo = ntohl(*(((uint32_t*) (opts + offset + 6))));
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
	static struct sendData sd;

	/* Finds the different headers+payload */
	//ethernet = (struct sniff_ethernet*) data;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipSize = ntohs(ip->ip_len);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	tcpHdrLen = TH_OFF(tcp) * 4;

	tmpConn = getConn(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport, &tcp->th_seq);

	/* Prepare packet data struct */
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.data.tstamp_pcap  = header->ts;
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestEndSeq, tmpConn->lastLargestSeqAbsolute);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.retrans      = false;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.flags        = tcp->th_flags;

	if (sd.data.payloadSize > 0) {
		sd.data.endSeq -= 1;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);

	sentPacketCount++;
	sentBytesCount += sd.data.payloadSize;

	if (sd.data.payloadSize > max_payload_size)
		max_payload_size = sd.data.payloadSize;

	if (tmpConn->registerSent(&sd))
		tmpConn->registerRange(&sd);
}


/*
  Used to test if a sequence number comes after another
  These handle when the newest sequence number has wrapped
*/
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
	uint64_t wrap_index;
	uint64_t seq_relative;
	wrap_index = firstSeq + largestSeq;
	wrap_index += 1;

	//printf("\nget_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u, wrap_index: %lu\n", seq, firstSeq, largestSeq, largestSeqAbsolute, wrap_index);
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
	if (seq_relative > 9999999999) {
		printf("wrap_index: %lu\n", wrap_index);
		printf("\nget_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u\n", seq, firstSeq, largestSeq, largestSeqAbsolute);
		printf("seq_relative: %lu\n", seq_relative);
		assert(0 && "Incorrect sequence number calculation!\n");
	}
	//printf("RETURN seq_relative: %lu\n", seq_relative);
	return seq_relative;
}

/* Process incoming ACKs */
void Dump::processAcks(const struct pcap_pkthdr* header, const u_char *data) {
	static const struct sniff_ip *ip; /* The IP header */
	static const struct sniff_tcp *tcp; /* The TCP header */
	static u_int ipHdrLen;
	static uint32_t ack;
	//static u_long eff_win;        /* window after scaling */
	static bool ret;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);

	static u_int tcpHdrLen;
	static uint tcpOptionLen;
	tcpHdrLen = TH_OFF(tcp) * 4;
	tcpOptionLen = tcpHdrLen - 20;

	Connection *tmpConn = getConn(&ip->ip_dst, &ip->ip_src, &tcp->th_dport, &tcp->th_sport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		cerr << "Ack for unregistered connection found. Ignoring. Conn: " << getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport) << endl;
		//exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	ack = ntohl(tcp->th_ack);

	DataSeg seg;
	memset(&seg, 0, sizeof(struct DataSeg));
	seg.ack         = get_relative_sequence_number(ack, tmpConn->rm->firstSeq, tmpConn->lastLargestAckSeq, tmpConn->lastLargestAckSeqAbsolute);
	seg.tstamp_pcap = header->ts;
	seg.window = ntohs(tcp->th_win);
	seg.flags  = tcp->th_flags;

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&seg, opt, tcpOptionLen);

	ret = tmpConn->registerAck(&seg);
	if (!ret) {
		printf("DUMP - failed to register ACK!\n");
	}
	else {
		tmpConn->lastLargestAckSeqAbsolute = ack;
		tmpConn->lastLargestAckSeq = seg.ack;
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

	colored_printf(YELLOW, "Processing receiver dump...\n");

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
	pcap_freecode(&compFilter);

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

	printf("Finished processing receiver dump...\n");
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

	tmpConn = getConn(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		static bool warning_printed = false;
		if (warning_printed == false) {
			cerr << "Connection found in recveiver dump that does not exist in sender: " << getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport);
			cerr << ". Maybe NAT is in effect?  Exiting." << endl;
			warn_with_file_and_linenum(__FILE__, __LINE__);
			warning_printed = true;
		}
		return;
	}

	/* Prepare packet data struct */
	struct sendData sd;
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestRecvEndSeq, tmpConn->lastLargestRecvSeqAbsolute);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.tstamp_pcap  = header->ts;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.retrans      = 0;
	sd.data.flags        = tcp->th_flags;
	sd.data.window       = ntohs(tcp->th_win);

	if (sd.data.seq == ULONG_MAX) {
		if (tmpConn->lastLargestRecvEndSeq == 0) {
			printf("Found invalid sequence numbers in beginning of receive dump. Probably the sender tcpdump didn't start in time to save this packets\n");
		}
		else {
			printf("Found invalid sequence number in received data!: %u -> %lu\n", sd.data.seq_absolute, sd.data.seq);
		}
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);
	recvPacketCount++;
	recvBytesCount += sd.data.payloadSize;
	tmpConn->registerRecvd(&sd);
}

void Dump::calculateRetransAndRDBStats() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->calculateRetransAndRDBStats();
	}
}

void Dump::printPacketDetails() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->rm->printPacketDetails();
	}
}


void Dump::fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns) {
	map<ConnectionMapKey*, Connection*>::iterator it, it_end;
	it_end = conns.end();
	for (it = conns.begin(); it != it_end; it++) {
		sortedConns.insert(pair<ConnectionMapKey*, Connection*>(it->first, it->second));
	}
}

void Dump::printConns() {
	map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> sortedConns;
	fillWithSortedConns(sortedConns);
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	struct connStats cs;
	struct connStats csAggregated;
	memset(&csAggregated, 0, sizeof(struct connStats));

	printf("\nConnections in sender dump: %lu\n\n", conns.size());
	printf("        %-30s   %-17s %-12s   %12s   %12s\n", "Conn key", "Duration (sec)", "Packets sent", "Bytes loss", "Ranges loss");
	for (cIt = sortedConns.begin(); cIt != sortedConns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addPacketStats(&cs);
		cIt->second->addPacketStats(&csAggregated);
		printf("   %-40s   %-17d   %-11d   %4.1f %%        %4.1f %%\n", cIt->second->getConnKey().c_str(), cs.duration,
		       cs.nrPacketsSent, (cs.bytes_lost / (double) cs.totBytesSent) * 100,
			   (cs.ranges_lost / (double) cs.ranges_sent) * 100);
	}
	printf("\n   %-40s   %-17d   %-11d   %4.1f %%        %4.1f %%\n", "Average", 0,
		   csAggregated.nrPacketsSent/(int)sortedConns.size(), (csAggregated.bytes_lost / (double) csAggregated.totBytesSent) * 100,
		   (csAggregated.ranges_lost / (double) csAggregated.ranges_sent) * 100);
}

/*
  Writes packet loss to file aggregated of GlobOpts::lossAggrSeconds in CSV format.
  loss-retr uses loss based on retransmissions.
  With receiver side dump, the actual loss is used in loss-lost.
*/
void Dump::write_loss_to_file() {
	FILE *loss_retr_file, *loss_lost_file = NULL;
	stringstream loss_retr_fn, loss_lost_fn;
	loss_retr_fn << GlobOpts::prefix << "loss-retr" << ".dat";
	loss_lost_fn << GlobOpts::prefix << "loss-lost" << ".dat";
	loss_retr_file = fopen(loss_retr_fn.str().c_str(), "w");

	if (GlobOpts::withRecv) {
		loss_lost_file = fopen(loss_lost_fn.str().c_str(), "w");
		if (loss_lost_file == NULL) {
			printf("Failed to open loss file for writing '%s'\n", loss_lost_fn.str().c_str());
			return;
		}
	}
	if (loss_retr_file == NULL) {
		printf("Failed to open loss file for writing '%s'\n", loss_retr_fn.str().c_str());
		return;
	}

	uint32_t timeslice_count = 0;

	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		timeslice_count = std::max(timeslice_count, cIt->second->getDuration(true));
	}

	unsigned timeslice = GlobOpts::lossAggrSeconds;

	timeslice_count /= timeslice;
	fprintf(loss_retr_file, "%45s %10u", " ", 0);
	if (GlobOpts::withRecv)
		fprintf(loss_lost_file, "%45s %10u", " ", 0);

	// print columns
	for (unsigned i = 1; i < timeslice_count; i++) {
		fprintf(loss_retr_file, ",%10u", i);
		if (GlobOpts::withRecv)
			fprintf(loss_lost_file, ",%10u", i);
	}
	fprintf(loss_retr_file, "\n");
	if (GlobOpts::withRecv)
		fprintf(loss_lost_file, "\n");


	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->rm->write_loss_over_time(timeslice, timeslice_count, loss_retr_file, loss_lost_file);
	}

	fclose(loss_retr_file);
	if (GlobOpts::withRecv)
		fclose(loss_lost_file);
}

void Dump::makeCDF() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->makeCDF();
	}
}

void Dump::writeCDF(){
	ofstream cdf_f;
	stringstream cdffn;
	cdffn << GlobOpts::prefix << "latency-cdf.dat";
	cdf_f.open((char*)((cdffn.str()).c_str()), ios::out);

	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->writeCDF(&cdf_f);
	}
	cdf_f.close();
}

void Dump::writeDcCdf(){
	ofstream dccdf_f;
	stringstream dccdffn;
	dccdffn << GlobOpts::prefix << "latency-dccdf.dat";
	dccdf_f.open((char*)((dccdffn.str()).c_str()), ios::out);

	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->writeDcCdf(&dccdf_f);
	}
	dccdf_f.close();
}

void Dump::writeAggCdf(){
	char print_buf[300];
	ofstream stream;
	stringstream filename;
	filename << GlobOpts::prefix << "latency-agg-cdf.dat";
	stream.open((char*)((filename.str()).c_str()), ios::out);

	map<const long, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = GlobStats::cdf.begin();
	nit_end = GlobStats::cdf.end();

	stream << endl << endl << "#Aggregated CDF:" << endl;
	stream << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
		sprintf(print_buf, "time: %10ld    CDF: %.10f\n", (*nit).first, cdfSum);
		stream << print_buf;
	}
}

void Dump::writeAggDcCdf(){
	char print_buf[300];
	ofstream stream;
	stringstream filename;
	filename << GlobOpts::prefix << "latency-agg-dccdf.dat";
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
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for(cIt = conns.begin(); cIt != conns.end(); cIt++){
		cIt->second->makeDcCdf();
	}
}

void Dump::printDumpStats() {
	cout << endl;
	colored_printf(YELLOW, "General info for entire dump:\n");
	printf("  %s:%s -> %s:%s\n", srcIp.c_str(), srcPort.c_str(), dstIp.c_str(), dstPort.c_str());
	cout << "  Filename: " << filename << endl;
	cout << "  Sent Packet Count     : " << sentPacketCount << endl;
	cout << "  Received Packet Count : " << recvPacketCount << endl;
	cout << "  ACK Count             : " << ackCount << endl;
	cout << "  Sent Bytes Count      : " << sentBytesCount << endl;
	cout << "  Max payload size      : " << max_payload_size;
	if (max_payload_size > 1460) {
		colored_printf(YELLOW, "   (Max payload for a packet is bigger than 1460. This may be caused by GSO/TSO (see readme))");
	}

	cout << endl;
/*
	if (GlobOpts::withRecv) {
		map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
		long int ranges_count = 0;
		long int ranges_lost = 0;
		long int ranges_sent = 0;
		uint64_t lost_bytes = 0;
		for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
			ranges_count += cIt->second->rm->getByteRangesCount();
			ranges_sent += cIt->second->rm->getByteRangesSent();
			ranges_lost += cIt->second->rm->getByteRangesLost();
			lost_bytes += cIt->second->rm->getLostBytes();
		}

		cout << "  Received Bytes        : " << recvBytesCount << endl;
		cout << "  Bytes Lost            : " << (lost_bytes) << endl;
		cout << "  Bytes Loss            : " << ((double) (lost_bytes) / sentBytesCount) * 100 <<  " \%" << endl;
		if ((sentPacketCount - recvPacketCount) < 0) {
			colored_printf(YELLOW, "Negative loss values is probably caused by GSO/TSO on sender side (see readme)\n");
		}
		cout << "  Packets Lost          : " << (sentPacketCount - recvPacketCount) << endl;
		cout << "  Packet  Loss          : " << ((double) (sentPacketCount - recvPacketCount) / sentPacketCount) * 100 <<  " \%" << endl;
		cout << "  Ranges Count          : " << (ranges_count) << endl;
		cout << "  Ranges Sent           : " << (ranges_sent) << endl;
		cout << "  Ranges Lost           : " << (ranges_lost) << endl;
		cout << "  Ranges Loss           : " << ((double) (ranges_lost) / ranges_sent) * 100 <<  " \%" << endl;
	}
*/
}

void Dump::genRFiles() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->genRFiles();
	}

	if (!GlobOpts::aggregate)
		return;

	vector<string> filenames = GlobStats::retrans_filenames;
	filenames.push_back("all-durations-");

	globStats->prefix_filenames(filenames);

	for (unsigned long int i = 0; i < filenames.size(); i++) {
		filenames[i] += "aggr.dat";
	}

	vector<int>::iterator it, it_end;
	unsigned long int i;
	for (i = 0; i < GlobStats::ack_latency_vectors.size(); i++) {
		ofstream stream;
		stream.open(filenames[i].c_str(), ios::out);
		it = GlobStats::ack_latency_vectors[i]->begin();
		it_end = GlobStats::ack_latency_vectors[i]->end();
		for (; it != it_end; it++) {
			stream << *it << endl;
		}
		stream.close();
	}

	ofstream stream;
	stream.open(filenames[i].c_str(), ios::out);
	// Handle duration data
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		stream << cIt->second->getDuration(true) << endl;
	}
	stream.close();
	i++;
}

void Dump::free_resources() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->first;
		delete cIt->second;
	}
}
