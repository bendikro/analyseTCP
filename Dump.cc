#include "Dump.h"
#include "color_print.h"
#include <memory>

extern GlobStats *globStats;
int GlobStats::totNumBytes;

/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string src_port, string dst_port, string fn) {
	timerclear(&first_sent_time);
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

	if (GlobOpts::validate_ranges) {
		/* DEBUG: Validate range */
		if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "---------------Begin first validation--------------" << endl;

		it_end = conns.end();
		for (it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
		if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
			cerr << "---------------End of first validation--------------" << endl;
	}

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

	if (GlobOpts::validate_ranges) {
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
}

void print_stats_separator(bool final) {
	char c = '-';
	if (final)
		c = '=';

	for (int i = 0; i < 63; i++)
		printf("%c", c);

	printf("\n");
	if (final)
		printf("\n");
}

// Update minimum values
void updateMinStats(struct BaseStats& aggStats, struct BaseStats& stats) {
	if (stats.min != -1 && (stats.min < aggStats.min))
		aggStats.min = stats.min;
	if (stats.max != -1 && stats.max < aggStats.max)
		aggStats.max = stats.max;
	if (stats.avg != -1 && stats.avg  < aggStats.avg)
		aggStats.avg = stats.avg;
}

// Update minimum values
void updateMaxStats(struct BaseStats& aggStats, struct BaseStats& stats) {
	if (stats.min != -1 && stats.min > aggStats.min)
		aggStats.min = stats.min;
	if (stats.max != -1 && stats.max > aggStats.max)
		aggStats.max = stats.max;
	if (stats.avg != -1 && stats.avg > aggStats.avg)
		aggStats.avg = stats.avg;
}

void Dump::writeITT(ofstream& stream, vector<struct SentTime>& sent_times) {
	for (size_t i = 0; i < sent_times.size(); i++) {
		stream << (sent_times[i].time) << "," << sent_times[i].itt << "," << sent_times[i].size << endl;
	}
}


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::printStatistics() {
	/* Initiate struct for aggregate stats */
	struct connStats cs, csAggregated;
	memset(&cs, 0, sizeof(struct connStats));
	memset(&csAggregated, 0, sizeof(struct connStats));

	byteStats bsAggregated, bsAggregatedMin, bsAggregatedMax;
	bsAggregatedMin.latency.min = bsAggregatedMin.latency.max = (numeric_limits<int64_t>::max)();
	bsAggregatedMin.packet_length.avg = bsAggregatedMin.latency.avg = bsAggregatedMin.itt.avg = (numeric_limits<double>::max)();
	bsAggregatedMin.packet_length.min = bsAggregatedMin.packet_length.max = (numeric_limits<int64_t>::max)();
	bsAggregatedMin.itt.min = bsAggregatedMin.itt.max = (numeric_limits<int64_t>::max)();

	csAggregated.rdb_byte_hits = 0;
	csAggregated.rdb_byte_misses = 0;
	csAggregated.rdb_bytes_sent = 0;

	int64_t max_value = (numeric_limits<int64_t>::max)();

	vector<string> itt_fnames;
	itt_fnames.push_back("itt-all.dat");
	globStats->prefix_filenames(itt_fnames);
	ofstream itt_stream;
	itt_stream.open(itt_fnames[0].c_str(), ios::out);
	itt_stream << "time,itt,payload_size" << endl;

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
			bs.percentiles_itt.init();
		}

		cIt->second->genBytesLatencyStats(&bs);

		//printf("cs->nrPacketsSent: %d\n", cs.nrPacketsSent);

		writeITT(itt_stream, bs.sent_times);

		if (!(GlobOpts::aggOnly)) {
			colored_printf(YELLOW, "STATS FOR CONN: %s:%u -> %s:%u", cIt->second->getSrcIp().c_str(), cIt->second->srcPort,
			       cIt->second->getDstIp().c_str(), cIt->second->dstPort);

			if (GlobOpts::analyse_start || GlobOpts::analyse_end || GlobOpts::analyse_duration) {
				colored_printf(YELLOW, " (Interval alalysed (sec): %d-%d)", cIt->second->rm->analyse_time_sec_start, cIt->second->rm->analyse_time_sec_end);
			}
			printf("\n");
			printPacketStats(&cs, &bs, false, NULL, NULL);
		}

		if (!(GlobOpts::aggOnly)) {
			printBytesLatencyStats(&cs, &bs, false, NULL, NULL);
			print_stats_separator(true);
		}

		if (GlobOpts::aggregate) {
			// Latency
			bsAggregated.latency += bs.latency;
			updateMinStats(bsAggregatedMin.latency, bs.latency);
			updateMaxStats(bsAggregatedMax.latency, bs.latency);

			// Add the latency values
			bsAggregated.latencies.insert(bsAggregated.latencies.end(), bs.latencies.begin(), bs.latencies.end());

			if (bs.packet_length.min != max_value) {
				bsAggregated.packet_length += bs.packet_length;
				updateMinStats(bsAggregatedMin.packet_length, bs.packet_length);
				updateMaxStats(bsAggregatedMax.packet_length, bs.packet_length);

				// Add the payload values
				bsAggregated.payload_lengths.insert(bsAggregated.payload_lengths.end(), bs.payload_lengths.begin(), bs.payload_lengths.end());
			}

			if (bs.itt.min != max_value) {
				// ITT
				bsAggregated.itt += bs.itt;
				updateMinStats(bsAggregatedMin.itt, bs.itt);
				updateMaxStats(bsAggregatedMax.itt, bs.itt);
				// Add the itt values
				bsAggregated.intertransmission_times.insert(bsAggregated.intertransmission_times.end(), bs.intertransmission_times.begin(), bs.intertransmission_times.end());
			}

			// Add retrans stats
			if ((uint64_t) bs.retrans.size() > bsAggregated.retrans.size()) {
				for (uint64_t i = bsAggregated.retrans.size(); i < bs.retrans.size(); i++) {
					bsAggregated.retrans.push_back(0);
				}
			}

			for (uint64_t i = 0; i < bs.retrans.size(); i++) {
				bsAggregated.retrans[i] += bs.retrans[i];
			}

			// Add dupack stats
			if ((uint64_t) bs.dupacks.size() > bsAggregated.dupacks.size()) {
				for (uint64_t i = bsAggregated.dupacks.size(); i < bs.dupacks.size(); i++) {
					bsAggregated.dupacks.push_back(0);
				}
			}

			for (uint64_t i = 0; i < bs.dupacks.size(); i++) {
				bsAggregated.dupacks[i] += bs.dupacks[i];
			}
		}
	}

	if (GlobOpts::aggregate) {
		if (csAggregated.nrPacketsSent) { /* To avoid division by 0 */
			csAggregated.duration /= sortedConns.size();

			bsAggregated.packet_length.min /= sortedConns.size();
			bsAggregated.packet_length.avg /= sortedConns.size();
			bsAggregated.packet_length.max /= sortedConns.size();

			bsAggregated.latency.min /= sortedConns.size();
			bsAggregated.latency.avg /= sortedConns.size();
			bsAggregated.latency.max /= sortedConns.size();

			bsAggregated.itt.min /= sortedConns.size();
			bsAggregated.itt.avg /= sortedConns.size();
			bsAggregated.itt.max /= sortedConns.size();

			bsAggregated.percentiles_lengths.init();
			bsAggregated.percentiles_latencies.init();
			bsAggregated.percentiles_itt.init();

			std::sort(bsAggregated.latencies.begin(), bsAggregated.latencies.end());
			percentiles(&bsAggregated.latencies, &bsAggregated.percentiles_latencies);
			std::sort(bsAggregated.payload_lengths.begin(), bsAggregated.payload_lengths.end());
			percentiles(&bsAggregated.payload_lengths, &bsAggregated.percentiles_lengths);
			std::sort(bsAggregated.intertransmission_times.begin(), bsAggregated.intertransmission_times.end());
			percentiles(&bsAggregated.intertransmission_times, &bsAggregated.percentiles_itt);

			cout << "\nAggregated Statistics for " << sortedConns.size() << " connections:" << endl;
			printPacketStats(&csAggregated, &bsAggregated, true, &bsAggregatedMin, &bsAggregatedMax);

			/* Print Aggregate bytewise latency */
			printBytesLatencyStats(&csAggregated, &bsAggregated, true, &bsAggregatedMin, &bsAggregatedMax);

			// ITT stats
			printPacketITTStats(&csAggregated, &bsAggregated, true, &bsAggregatedMin, &bsAggregatedMax);
			print_stats_separator(true);
		}
	}
	itt_stream.close();
}


void Dump::printPacketStats(connStats *cs, byteStats *bs, bool aggregated, byteStats* aggregatedMin, byteStats* aggregatedMax) {
	printf("  Duration: %u seconds (%f hours)\n", cs->duration, ((double) cs->duration / 60 / 60));

	if (cs->nrPacketsSent != cs->nrPacketsSentFoundInDump) {
		printf("  Total packets sent (adj. for fragmentation)   : %10d\n", cs->nrPacketsSent);
		printf("  Total packets sent (found in dump)            : %10d\n", cs->nrPacketsSentFoundInDump);
		printf("  Total data packets sent (adj.)                : %10d\n", cs->nrDataPacketsSent);
		printf("  Total data packets sent (found)               : %10d\n", cs->nrDataPacketsSent - (cs->nrPacketsSent - cs->nrPacketsSentFoundInDump));
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
		   "  Number of packets with redundant data         : %10d\n"	\
		   "  Number of received acks                       : %10d\n"   \
	       "  Total bytes sent (payload)                    : %10llu\n"	\
	       "  Number of unique bytes                        : %10llu\n"   \
	       "  Number of retransmitted bytes                 : %10d\n"	\
		   "  Redundant bytes (bytes already sent)          : %10llu (%.2f %%)\n",
		   cs->pureAcksCount, syn_fin_rst,
		   cs->nrRetrans, cs->bundleCount, cs->nrRetrans - cs->nrRetransNoPayload + cs->bundleCount, cs->ackCount, cs->totBytesSent,
	       cs->totUniqueBytesSent, cs->totRetransBytesSent, cs->totBytesSent - cs->totUniqueBytesSent,
	       safe_div((cs->totBytesSent - cs->totUniqueBytesSent), cs->totBytesSent) * 100);

	if (cs->totUniqueBytesSent != cs->totUniqueBytes) {
		colored_printf(RED, "  Trace is missing segments. Bytes missing      : %10d\n", cs->totUniqueBytes - cs->totUniqueBytesSent);
	}

	if (cs->nrPacketsSent != cs->nrPacketsSentFoundInDump) {
		printf("  Estimated loss rate based on retransmission\n");
		printf("    Based on sent pkts (adj. for fragmentation) : %10.2f %%\n",
			   safe_div(cs->nrRetrans, cs->nrPacketsSent) * 100);
		printf("    Based on sent pkts (found in dump)          : %10.2f %%\n",
			   safe_div(cs->nrRetrans, cs->nrPacketsSentFoundInDump) * 100);

	}
	else {
		printf("  Estimated loss rate based on retransmissions  : %10.2f %%\n",
			   safe_div(cs->nrRetrans, cs->nrPacketsSent) * 100);
	}

	if (GlobOpts::withRecv && cs->ranges_sent) {
		print_stats_separator(false);
		printf("Receiver side loss stats:\n");
		printf("  Number of packets received                    : %10d\n", cs->nrPacketsReceivedFoundInDump);
		printf("  Packets lost                                  : %10d\n", (cs->nrPacketsSentFoundInDump - cs->nrPacketsReceivedFoundInDump));
		printf("  Packet loss                                   : %10.2f %%\n",  safe_div((cs->nrPacketsSentFoundInDump - cs->nrPacketsReceivedFoundInDump), cs->nrPacketsSentFoundInDump) * 100);

		printf("  Bytes Lost (actual loss on receiver side)     : %10llu\n", cs->bytes_lost);
		printf("  Bytes Loss                                    : %10.2f %%\n", safe_div(cs->bytes_lost, cs->totBytesSent) * 100);
		printf("  Ranges Lost (actual loss on receiver side)    : %10llu\n", cs->ranges_lost);
		printf("  Ranges Loss                                   : %10.2f %%\n", safe_div(cs->ranges_lost, cs->ranges_sent) * 100);
	}

	print_stats_separator(false);
	printf("Payload size stats:\n");

	if (aggregated) {
		printf("  Average of all packets in all connections     : %10d\n",
		       (int) floorf((double) safe_div(cs->totBytesSent, cs->nrDataPacketsSent)));
		printf("  Average of the average for each connection    : %10d\n", (int) bs->packet_length.avg);
	}
	else {
		printf("  Average                                       : %10d\n", (int) bs->packet_length.avg);
	}

	if (bs != NULL) {
		if (aggregated) {
			printAggStats("payload", "bytes", cs, bs->packet_length, aggregatedMin->packet_length, aggregatedMax->packet_length);
		}
		else {
			printStats("payload", "bytes", bs->packet_length);
		}

		if (bs->percentiles_lengths.percentiles.size()) {
			bs->percentiles_lengths.print("  %*sth percentile %-26s    : %10.0f\n", true);
		}
	}

	if (cs->rdb_bytes_sent) {
		print_stats_separator(false);
		printf("RDB stats:\n");
		printf("  RDB packets                                   : %10d (%.2f%% of data packets sent)\n", cs->bundleCount, safe_div(cs->bundleCount, cs->nrDataPacketsSent) * 100);
		printf("  RDB bytes bundled                             : %10llu (%.2f%% of total bytes sent)\n", cs->rdb_bytes_sent, safe_div(cs->rdb_bytes_sent, cs->totBytesSent) * 100);

		if (GlobOpts::withRecv) {
			printf("  RDB packet hits                               : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_hits, safe_div(cs->rdb_packet_hits, cs->bundleCount) * 100);
			printf("  RDB packet misses                             : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_misses, safe_div(cs->rdb_packet_misses, cs->bundleCount) * 100);
			printf("  RDB byte hits                                 : %10llu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   cs->rdb_byte_hits, safe_div(cs->rdb_byte_hits, cs->rdb_bytes_sent) * 100, safe_div(cs->rdb_byte_hits, cs->totBytesSent) * 100);
			printf("  RDB byte misses                               : %10llu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   cs->rdb_byte_misses, safe_div(cs->rdb_byte_misses, cs->rdb_bytes_sent) * 100, safe_div(cs->rdb_byte_misses, cs->totBytesSent) * 100);
		}
	}
}


/* Generate statistics for bytewise latency */
void Dump::printPacketITTStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax) {
	print_stats_separator(false);
	printf("ITT stats");

 	if (aggregated) {
		printf(" (Average for all the connections)\n");
	}
	else
		printf(":\n");

	if (aggregated) {
		printAggStats("ITT", "ms", cs, bs->itt, aggregatedMin->itt, aggregatedMax->itt);
	}
	else {
		printStats("itt", "ms", bs->itt);
	}

	if (bs->percentiles_itt.percentiles.size()) {
		bs->percentiles_itt.print("  %*sth percentile %-26s    : %10.0f ms\n", true);
	}
}


void Dump::printStats(string prefix, string unit, struct BaseStats& bs) {
	printf("  Minimum %10s                            : %7llu %s\n", prefix.c_str(), bs.min, unit.c_str());
	printf("  Average %10s                            : %7.0f %s\n", prefix.c_str(), bs.avg, unit.c_str());
	printf("  Maximum %10s                            : %7llu %s\n", prefix.c_str(), bs.max, unit.c_str());
}

void Dump::printAggStats(string prefix, string unit, struct connStats *cs, struct BaseStats& bs, struct BaseStats& aggregatedMin, struct BaseStats& aggregatedMax) {
	if (aggregatedMin.min == (numeric_limits<int64_t>::max)())
		aggregatedMin.min = aggregatedMin.avg = aggregatedMin.max = 0;

	printf("  Minimum %10s (min, avg, max)            :    %7lld, %7lld, %7lld %s\n", prefix.c_str(), aggregatedMin.min, bs.min, aggregatedMax.min, unit.c_str());
	printf("  Average %10s (min, avg, max)            :    %7.0f, %7.0f, %7.0f %s\n", prefix.c_str(), aggregatedMin.avg, bs.avg, aggregatedMax.avg, unit.c_str());
	printf("  Maximum %10s (min, avg, max)            :    %7lld, %7lld, %7lld %s\n", prefix.c_str(), aggregatedMin.max, bs.max, aggregatedMax.max, unit.c_str());
	printf("  Average for all packets in all conns          : %10lld ms\n", bs.cum / cs->nrPacketsSent);
}


/* Generate statistics for bytewise latency */
void Dump::printBytesLatencyStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax) {
	print_stats_separator(false);
	printf("Latency stats");

	if (aggregated) {
		printf(" (Average for all the connections)\n");
	}
	else
		printf(":\n");

	if (aggregated) {
		printAggStats("latencies", "ms", cs, bs->latency, aggregatedMin->latency, aggregatedMax->latency);

		if (GlobOpts::verbose) {
			printf("\nAggregated latency values explained:\n"
				   "Minimum min: The smallest value of all the minimum latencies for each connection\n"
				   "Minimum avg: The average of all the minimum latency values for all connections\n"
				   "Minimum max: The biggest value of all the minimum latencies for each connection\n"
				   "Average min: Calculate the average latency for each connection. This is the smallest calculated average\n"
				   "Average avg: Calculate the average latency for each connection. This is the average of all the calculated averages\n"
				   "Average max: Calculate the average latency for each connection. This is the biggest calculated average\n"
				   "Maximum min: The smallest value of all the maximum latencies for each connection\n"
				   "Maximum avg: The average of all the maximum latency values for all connections\n"
				   "Maximum max: The biggest value of all the maximum latencies for each connection\n"
				);
		}
	}
	else {
		printStats("latency", "ms", bs->latency);
	}

	if (bs->percentiles_latencies.percentiles.size()) {
		bs->percentiles_latencies.print("  %*sth percentile %-26s    : %10.0f ms\n", true);
	}

	if (GlobOpts::verbose) {
		vector<int>::reverse_iterator curr;
		int value;

		vector<int> retrans_accumed = bs->retrans;
		for (value = 0, curr = retrans_accumed.rbegin(); curr != retrans_accumed.rend(); ++curr) {
			*curr += value;
			value = *curr;
		}

		print_stats_separator(false);
		printf("  Max retransmissions                           : %10lu \n", bs->retrans.size());
		for (uint64_t i = 0; i < bs->retrans.size(); i++) {
			if ((GlobOpts::verbose < 2) && i > 2)
				break;
			if (bs->retrans[i] == 0)
				break;
			printf("  %2llu. retransmission (count / accumulated)      : %6d / %d\n", i+1, bs->retrans[i], retrans_accumed[i]);
		}
		print_stats_separator(false);

		vector<int> dupacks_accumed = bs->dupacks;
		for (value = 0, curr = dupacks_accumed.rbegin(); curr != dupacks_accumed.rend(); ++curr) {
			*curr += value;
			value = *curr;
		}
		printf("  Max dupacks                                   : %10lu \n", bs->dupacks.size());
		for (uint64_t i = 0; i < bs->dupacks.size(); i++) {
			if ((GlobOpts::verbose > 1) || i < 3)
				printf("  %2llu. dupacks (count / accumulated)             : %6d / %d\n", i+1, bs->dupacks[i], dupacks_accumed[i]);
			//printf("  Occurrences of %2lu. dupacks                   : %d\n", i + 1, bs->dupacks[i]);
		}
	}
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
void Dump::processSent(const pcap_pkthdr* header, const u_char *data) {
	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	u_int ipSize;
	u_int ipHdrLen;
	u_int tcpHdrLen;

	/* Finds the different headers+payload */
	//ethernet = (struct sniff_ethernet*) data;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipSize = ntohs(ip->ip_len);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	tcpHdrLen = TH_OFF(tcp) * 4;

	Connection* tmpConn = getConn(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport, &tcp->th_seq);

	/* Prepare packet data struct */
	sendData sd;
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.data.tstamp_pcap  = header->ts;
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestEndSeq, tmpConn->lastLargestSeqAbsolute, tmpConn);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.retrans      = false;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.flags        = tcp->th_flags;

	if (sd.data.seq == ULONG_MAX) {
		if (sd.data.flags & TH_SYN) {
			fprintf(stdout, "Found invalid sequence numbers in beginning of sender dump. Probably old SYN packets\n");
			return;
		}

		printf("Found invalid sequence numbers in beginning of sender dump. Probably the sender dump has retransmissions of packets before the first packet in dump\n");
		return;
	}

	if (first_sent_time.tv_sec == 0 && first_sent_time.tv_usec == 0) {
		first_sent_time = header->ts;
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

	if (GlobOpts::withThroughput) {
		tmpConn->registerPacketSize(first_sent_time, header->ts, header->len, sd.data.payloadSize);
	}
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
uint64_t Dump::get_relative_sequence_number(uint32_t seq, uint32_t firstSeq, uint64_t largestSeq, uint32_t largestSeqAbsolute, Connection *conn) {
	uint64_t wrap_index;
	uint64_t seq_relative;
	wrap_index = firstSeq + largestSeq;
	wrap_index += 1;

	//printf("get_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u, wrap_index: %lu\n", seq, firstSeq, largestSeq, largestSeqAbsolute, wrap_index);
	// Either seq has wrapped, or a retrans (or maybe reorder if netem is run on sender machine)
	if (seq < largestSeqAbsolute) {
		// This is an earlier sequence number
		if (before(seq, largestSeqAbsolute)) {
			if (before(seq, firstSeq)) {
				return ULONG_MAX;
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
		//fprintf(stderr, "\nget_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u\n", seq, firstSeq, largestSeq, largestSeqAbsolute);
		//fprintf(stderr, "seq_relative: %lu\n", seq_relative);
		//fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());
		
#if !defined(NDEBUG) && defined(DEBUG)
		fprintf(stderr, "Encountered invalid sequence number for connection %s: %u (firstSeq=%u, largestSeq=%lu, largestSeqAbsolute=%u\n",
				conn->getConnKey().c_str(),
				seq,
				firstSeq,
				largestSeq,
				largestSeqAbsolute);
#endif

		//assert(0 && "Incorrect sequence number calculation!\n");
		return ULONG_MAX;
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
		return;
	}
	ack = ntohl(tcp->th_ack);

	DataSeg seg;
	memset(&seg, 0, sizeof(struct DataSeg));
	seg.ack         = get_relative_sequence_number(ack, tmpConn->rm->firstSeq, tmpConn->lastLargestAckSeq, tmpConn->lastLargestAckSeqAbsolute, tmpConn);
	seg.tstamp_pcap = header->ts;
	seg.window = ntohs(tcp->th_win);
	seg.flags  = tcp->th_flags;

	if (seg.ack == ULONG_MAX) {
		fprintf(stdout, "Invalid sequence number for ACK! (SYN=%d)\n", !!(seg.flags & TH_SYN));
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&seg, opt, tcpOptionLen);

	ret = tmpConn->registerAck(&seg);
	if (!ret) {
		if (GlobOpts::validate_ranges) {
			printf("DUMP - failed to register ACK!\n");
		}
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

	if (tmpConn->lastLargestRecvEndSeq == 0 &&
		ntohl(tcp->th_seq) != tmpConn->rm->firstSeq) {
	    if (tcp->th_flags & TH_SYN) {
			printf("Invalid sequence number in SYN packet. This is probably an old connection - discarding...\n");
			return;
		}
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
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestRecvEndSeq, tmpConn->lastLargestRecvSeqAbsolute, tmpConn);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.tstamp_pcap  = header->ts;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.retrans      = 0;
	sd.data.in_sequence  = 0;
	sd.data.flags        = tcp->th_flags;
	sd.data.window       = ntohs(tcp->th_win);

	if (sd.data.seq == ULONG_MAX) {
		if (sd.data.flags & TH_SYN) {
			fprintf(stdout, "Found invalid sequence numbers in beginning of receive dump. Probably an old SYN packet\n");
			return;
		}

		if (tmpConn->lastLargestRecvEndSeq == 0) {
			printf("Found invalid sequence numbers in beginning of receive dump. Probably the sender tcpdump didn't start in time to save this packets\n");
		}
		else {
			printf("Found invalid sequence number in received data!: %u -> %llu\n", sd.data.seq_absolute, sd.data.seq);
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

	if (!GlobOpts::withRecv) {
		colored_printf(RED, "Loss statistics require reciver dump!\n");
	}

	printf("\nConnections in sender dump: %lu\n\n", conns.size());
	printf("        %-30s   %-17s %-12s   %-12s   ", "Conn key", "Duration (sec)", "Loss (est)", "Packets sent");

	if (GlobOpts::withRecv) {
		printf(" %12s   %12s %12s  %12s", "Packets recv", "Packet loss", "Byte loss", "Range loss");
	}
	printf("\n");

	char loss_estimated[50];

	for (cIt = sortedConns.begin(); cIt != sortedConns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addPacketStats(&cs);
		cIt->second->addPacketStats(&csAggregated);

		if (cs.nrPacketsSent != cs.nrPacketsSentFoundInDump) {
			sprintf(loss_estimated, "%.2f / %.2f", ((double) cs.nrRetrans / cs.nrPacketsSent) * 100, ((double) cs.nrRetrans / cs.nrPacketsSentFoundInDump) * 100);
		}
		else {
			sprintf(loss_estimated, "%.2f / %.2f", ((double) cs.nrRetrans / cs.nrPacketsSent) * 100, ((double) cs.nrRetrans / cs.nrPacketsSentFoundInDump) * 100);
		}
		printf("   %-40s %-13d %-15s  %-14d", (cIt->second->getConnKey() + ":").c_str(), cs.duration, loss_estimated, cs.nrPacketsSentFoundInDump);

		if (GlobOpts::withRecv) {
			printf("  %-11d  %8.2f %%     %8.2f %%   %8.2f %%",
				   cs.nrPacketsReceivedFoundInDump,
				   (((double) ((cs.nrPacketsSentFoundInDump - cs.nrPacketsReceivedFoundInDump)) / cs.nrPacketsSentFoundInDump) * 100),
				   (cs.bytes_lost / (double) cs.totBytesSent) * 100,
				   (cs.ranges_lost / (double) cs.ranges_sent) * 100);
		}
		printf("\n");
	}

	if (GlobOpts::verbose >= 3) {
		printf("\n   %-40s   %-17d   %-11d   %4.1f %%        %4.1f %%\n", "Average", 0,
			   csAggregated.nrPacketsSentFoundInDump/(int)sortedConns.size(), (csAggregated.bytes_lost / (double) csAggregated.totBytesSent) * 100,
			   (csAggregated.ranges_lost / (double) csAggregated.ranges_sent) * 100);
	}

	if (csAggregated.nrPacketsSentFoundInDump != csAggregated.nrPacketsSent) {
		colored_printf(YELLOW, "Note: Packets in trace dumps may differ from actual packets due to offloading\n");
	}

	printf("\n");
}


/*
 * Writes number of bytes and packets sent aggregated over time slices to file (throughput)
 */
void Dump::writeByteCountGroupedByInterval() {
	map<ConnectionMapKey*, Connection*>::iterator conn;

	if (GlobOpts::aggregate) {
		auto_ptr< vector< pair<uint64_t,uint64_t> > > all_sizes(new vector< pair<uint64_t,uint64_t> >);

		uint64_t idx, num;
		for (conn = conns.begin(); conn != conns.end(); conn++) {
			for (idx = 0, num = conn->second->packetSizes.size(); idx < num; ++idx) {

				vector< pair<uint64_t,uint64_t> >& all = *all_sizes.get();
				while (idx >= all.size()) {
					all.push_back(pair<uint64_t, uint64_t>(0, 0));
				}

				const uint64_t count = conn->second->packetSizes[idx].size();
				uint64_t bytes = 0;

				vector<struct PacketSize>::iterator it, end;
				it = conn->second->packetSizes[idx].begin();
				end = conn->second->packetSizes[idx].end();

				for (; it != end; ++it) {
					bytes += it->packet_size;
				}

				const pair<uint64_t,uint64_t>& old = all[idx];
				all[idx] = pair<uint64_t, uint64_t>(old.first + count, old.second + bytes);
			}
		}

		ofstream stream;
		stream.open((GlobOpts::prefix + "throughput-aggr.dat").c_str(), ios::out);
		stream << "interval" << "," << "packet_count" << "," << "byte_count" << "," << "throughput" << endl;

		for (idx = 0, num = all_sizes->size(); idx < num; ++idx) {
			const pair<uint64_t, uint64_t>& value = all_sizes->at(idx);
			stream << idx << "," << value.first << "," << value.second << ",";
			stream << (value.second * 8.0) / (GlobOpts::throughputAggrMs / 1000.0) << endl;
		}

		stream.close();
	}

	if (!GlobOpts::aggOnly) {
		for (conn = conns.begin(); conn != conns.end(); conn++) {
			ofstream stream;
			stream.open((GlobOpts::prefix + "throughput-" + conn->second->getConnKey() + ".dat").c_str(), ios::out);
			stream << "interval" << "," << "packet_count" << "," << "byte_count" << "," << "throughput" << endl;

			uint64_t idx, num;
			for (idx = 0, num = conn->second->packetSizes.size(); idx < num; ++idx) {

				const uint64_t count = conn->second->packetSizes[idx].size();
				uint64_t bytes = 0;

				vector<struct PacketSize>::iterator it, end;
				it = conn->second->packetSizes[idx].begin();
				end = conn->second->packetSizes[idx].end();

				for (; it != end; ++it) {
					bytes += it->packet_size;
				}

				stream << idx << "," << count << "," << bytes << ",";
				stream << (bytes * 8.0) / (GlobOpts::throughputAggrMs / 1000.0) << endl;
			}

			stream.close();
		}
	}
}


/*
 * Output a loss interval value to an output file stream
 */
ofstream& operator<<(ofstream& s, const LossInterval& v) {
	// total sent during interval
	s << v.tot_cnt_bytes << ",";
	s << v.tot_all_bytes << ",";
	s << (v.tot_all_bytes - v.tot_new_bytes) << ",";
	s << v.tot_new_bytes << ",";

	// total lost during interval
	s << v.cnt_bytes << ",";
    s << v.all_bytes << ",";
	s << (v.all_bytes - v.new_bytes) << ",";
	s << v.new_bytes << ",";

	// total lost relative to sent within interval
	if (v.tot_cnt_bytes != 0)
		s << (v.cnt_bytes / v.tot_cnt_bytes) << ",";
	else
		s << 0 << ",";

	if (v.tot_all_bytes != 0)
		s << (v.all_bytes / v.tot_all_bytes) << ",";
	else
		s << 0 << ",";

	if ((v.tot_all_bytes - v.tot_new_bytes) != 0)
		s << ((v.all_bytes - v.new_bytes) / (v.tot_all_bytes - v.tot_new_bytes)) << ",";
	else
		s << 0 << ",";

	if (v.tot_new_bytes != 0)
		s << (v.new_bytes / v.tot_new_bytes) << ",";
	else
		s << 0 << ",";

	// total lost relative to lost within interval
	if (v.all_bytes != 0)
		s << ((v.all_bytes - v.new_bytes) / v.all_bytes) << ",";
	else
		s << 0 << ",";

	if (v.all_bytes != 0)
		s << (v.new_bytes / v.all_bytes);
	else
		s << 0;

	return s;
}

/*
 * Writes loss to file
 * The columns are ordered as follows:
 * 0  interval index
 * 1  byte ranges sent within interval
 * 2  all bytes sent (incl. retrans) within interval
 * 3  old bytes sent (retrans only) within interval
 * 4  new bytes sent (new data) within interval
 * 5  ranges lost within interval
 * 6  all bytes lost (incl. retrans) within interval
 * 7  old bytes lost (retrans) within interval
 * 8  new bytes lost (new data) within interval
 * 9  ranges lost relative to ranges sent within interval
 * 10 all bytes lost relative to all bytes sent within interval
 * 11 old bytes lost relative to old bytes sent within interval
 * 12 new bytes lost relative to new bytes sent within interval
 * 13 old bytes lost relative to all bytes lost within interval
 * 14 new bytes lost relative to all bytes lost within interval
 * 15 ranges lost relative to total ranges sent
 * 16 bytes lost relative to total bytes sent
 */
void Dump::write_loss_to_file() {
	assert(GlobOpts::withRecv && "Calculating loss is only possible with receiver dump");

	auto_ptr< vector<LossInterval> > aggr( new vector<LossInterval>() );
	double total_count = 0, total_bytes = 0;

	const char* headers[] = {
		"interval",
		"ranges_sent", "all_bytes_sent", "old_bytes_sent", "new_bytes_sent",
		"ranges_lost", "all_bytes_lost", "old_bytes_lost", "new_bytes_lost",
		"ranges_lost_relative_to_interval", "all_bytes_lost_relative_to_interval", "old_bytes_lost_relative_to_interval", "new_bytes_lost_relative_to_interval",
		"old_bytes_lost_relative_to_all_bytes_lost", "new_bytes_lost_relative_to_all_bytes_lost",
		"ranges_lost_relative_to_total", "all_bytes_lost_relative_to_total"
	};

	// Extract (and print) loss values for each connection
	map<ConnectionMapKey*, Connection*>::iterator conn;
	for (conn = conns.begin(); conn != conns.end(); ++conn) {

		unique_ptr< vector<LossInterval> > loss(new vector<LossInterval>());

		conn->second->rm->calculateLossGroupedByInterval(TV_TO_MS(first_sent_time), *aggr, *loss);
		total_count += conn->second->rm->analysed_sent_ranges_count;
		total_bytes += conn->second->rm->analysed_bytes_sent;

		// output to stream
		if (!GlobOpts::aggOnly) {
			string filename;
			filename = GlobOpts::prefix + "loss-" + conn->second->getConnKey() + ".dat";

			ofstream stream;
			stream.open(filename.c_str(), ios::out);

			stream << headers[0];
			for (uint64_t idx = 1; idx < sizeof(headers) / sizeof(headers[0]); ++idx) {
				stream << "," << headers[idx];
			}
			stream << endl;

			for (uint64_t idx = 0, num = loss->size(); idx < num; ++idx) {

				// lost ranges&bytes relative to total ranges&bytes
				const double rel_count = loss->at(idx).cnt_bytes / (double) conn->second->rm->analysed_sent_ranges_count;
				const double rel_bytes = loss->at(idx).all_bytes / (double) conn->second->rm->analysed_bytes_sent;

				stream << idx << ",";
				stream << loss->at(idx) << ",";
				stream << rel_count << "," << rel_bytes << endl;
			}

			stream.close();
		}
	}

	// Print values for all connections
	if (GlobOpts::aggregate) {
		ofstream stream;
		stream.open((GlobOpts::prefix + "loss-aggr.dat").c_str(), ios::out);

		stream << headers[0];
		for (uint64_t idx = 1; idx < sizeof(headers) / sizeof(headers[0]); ++idx) {
			stream << "," << headers[idx];
		}
		stream << endl;

		for (uint64_t idx = 0, num = aggr->size(); idx < num; ++idx) {

			// lost ranges&bytes relative to total ranges&bytes
			const double rel_count = aggr->at(idx).cnt_bytes / total_count;
			const double rel_bytes = aggr->at(idx).all_bytes / total_bytes;

			// output to stream
			stream << idx << ",";
			stream << aggr->at(idx) << ",";
			stream << rel_count << "," << rel_bytes << endl;
		}

		stream.close();
	}
}


void Dump::calculateLatencyVariation() {
	map<ConnectionMapKey*, Connection*>::iterator it;
	for (it = conns.begin(); it != conns.end(); ++it) {
		it->second->calculateLatencyVariation();
	}
}

void Dump::makeByteLatencyVariationCDF() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->makeByteLatencyVariationCDF();
	}
}

void Dump::writeSentTimesAndQueueingDelayVariance() {
	map<ConnectionMapKey*, Connection*>::iterator it;
	const uint64_t first_tstamp = TV_TO_MS(first_sent_time);

	ofstream all_stream;
	all_stream.open((GlobOpts::prefix + "queueing-delay-all.dat").c_str(), ios::out);

	for (it = conns.begin(); it != conns.end(); ++it) {
		it->second->writeSentTimesAndQueueingDelayVariance(first_tstamp, all_stream);

		string filename;
		filename = GlobOpts::prefix + "queueing-delay-" + it->second->getConnKey() + ".dat";

		ofstream stream;
		stream.open(filename.c_str(), ios::out);
		it->second->writeSentTimesAndQueueingDelayVariance(first_tstamp, stream);
		stream.close();
	}
	all_stream.close();
}

void Dump::writeByteLatencyVariationCDF() {
	ofstream cdf_f;
	stringstream cdffn;
	cdffn << GlobOpts::prefix << "latency-variation-cdf.dat";
	cdf_f.open((char*)((cdffn.str()).c_str()), ios::out);

	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->writeByteLatencyVariationCDF(&cdf_f);
	}
	cdf_f.close();
}

void Dump::writeAggByteLatencyVariationCDF() {
	char print_buf[300];
	ofstream stream;
	stringstream filename;
	filename << GlobOpts::prefix << "latency-variation-aggr-cdf.dat";
	stream.open((char*)((filename.str()).c_str()), ios::out);

	map<const long, int>::iterator nit, nit_end;
	double cdfSum = 0;
	nit = GlobStats::byteLatencyVariationCDFValues.begin();
	nit_end = GlobStats::byteLatencyVariationCDFValues.end();

	stream << endl << endl << "#Aggregated CDF:" << endl;
	stream << "#Relative delay      Percentage" << endl;
	for(; nit != nit_end; nit++){
		cdfSum += (double)(*nit).second / GlobStats::totNumBytes;
		sprintf(print_buf, "time: %10ld    CDF: %.10f\n", (*nit).first, cdfSum);
		stream << print_buf;
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

	if (GlobOpts::withRecv) {
		map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
		long int ranges_count = 0;
		long int ranges_lost = 0;
		long int ranges_sent = 0;
		for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
			ranges_count += cIt->second->rm->getByteRangesCount();
			ranges_sent += cIt->second->rm->getByteRangesSent();
			ranges_lost += cIt->second->rm->getByteRangesLost();
		}
		cout << "  Received Bytes        : " << recvBytesCount << endl;
		if ((sentPacketCount - recvPacketCount) < 0) {
			colored_printf(YELLOW, "Negative loss values is probably caused by GSO/TSO on sender side (see readme)\n");
		}
		cout << "  Packets Lost          : " << (sentPacketCount - recvPacketCount) << endl;
		cout << "  Packet Loss           : " << ((double) (sentPacketCount - recvPacketCount) / sentPacketCount) * 100 <<  " %" << endl;
		cout << "  Ranges Count          : " << (ranges_count) << endl;
		cout << "  Ranges Sent           : " << (ranges_sent) << endl;
		cout << "  Ranges Lost           : " << (ranges_lost) << endl;
	}
}

void Dump::genAckLatencyFiles() {
	map<ConnectionMapKey*, Connection*>::iterator cIt = conns.begin();

	const long first_ts = TV_TO_MS(first_sent_time);

	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->genAckLatencyFiles(first_ts);
	}

	if (!GlobOpts::aggregate)
		return;

	vector<string> filenames = GlobStats::retrans_filenames;
	filenames.push_back("durations-all-");

	globStats->prefix_filenames(filenames);

	for (unsigned long int i = 0; i < filenames.size(); i++) {
		filenames[i] += "aggr.dat";
	}

	vector<LatencyItem>::iterator it, it_end;
	unsigned long int i;
	for (i = 0; i < GlobStats::ack_latency_vectors.size(); i++) {
		ofstream stream;
		stream.open(filenames[i].c_str(), ios::out);
		it = GlobStats::ack_latency_vectors[i]->begin();
		it_end = GlobStats::ack_latency_vectors[i]->end();
		for (; it != it_end; it++) {
			stream << it->str() << endl;
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

void Dump::writePacketByteCountAndITT() {
	map<ConnectionMapKey*, Connection*>::iterator it;

	ofstream* all_stream = NULL;
	ofstream* conn_stream = NULL;
	string header("timestamp,itt,payload_size,packet_size");

	if (GlobOpts::aggregate) {
		all_stream = new ofstream;
		all_stream->open((GlobOpts::prefix + "packet-byte-count-and-itt-all.dat").c_str(), ios::out);
		*all_stream << header << endl;
	}

	for (it = conns.begin(); it != conns.end(); ++it) {

		if (!GlobOpts::aggOnly) {
			string filename (GlobOpts::prefix + "packet-byte-count-and-itt-" + it->second->getConnKey() + ".dat");
			conn_stream = new ofstream;
			conn_stream->open(filename.c_str(), ios::out);
			*conn_stream << header << endl;
		}

		it->second->writePacketByteCountAndITT(all_stream, conn_stream);

		if (!GlobOpts::aggOnly) {
			conn_stream->close();
			delete conn_stream;
		}
	}

	if (GlobOpts::aggregate) {
		all_stream->close();
		delete all_stream;
	}
}


void Dump::free_resources() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->first;
		delete cIt->second;
	}
}
