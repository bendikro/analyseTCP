#include "Dump.h"
#include "Statistics.h"
#include "color_print.h"

Statistics::Statistics(Dump &d)
    : dump(d)
{
}

void Statistics::fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns) {
	map<ConnectionMapKey*, Connection*>::iterator it, it_end;
	it_end = dump.conns.end();
	for (it = dump.conns.begin(); it != it_end; it++) {
		sortedConns.insert(pair<ConnectionMapKey*, Connection*>(it->first, it->second));
	}
}

void Statistics::printConns() {
	map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> sortedConns;
	fillWithSortedConns(sortedConns);
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	struct connStats cs;
	struct connStats csAggregated;
	memset(&csAggregated, 0, sizeof(struct connStats));

	if (!GlobOpts::withRecv) {
		colored_printf(RED, "Loss statistics require reciver dump!\n");
	}

	printf("\nConnections in sender dump: %lu\n\n", dump.conns.size());
	printf("        %-30s   %-17s %-12s   %-12s   ", "Conn key", "Duration (sec)", "Loss (est)", "Packets sent");

	if (GlobOpts::withRecv) {
		printf(" %12s   %12s %12s  %12s", "Packets recv", "Packet loss", "Byte loss", "Range loss");
	}
	printf("\n");

	char loss_estimated[50];

	for (cIt = sortedConns.begin(); cIt != sortedConns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addConnStats(&cs);
		cIt->second->addConnStats(&csAggregated);

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


void Statistics::printDumpStats() {
	cout << endl;
	colored_printf(YELLOW, "General info for entire dump:\n");
	printf("  %s:%s -> %s:%s\n", dump.srcIp.c_str(), dump.srcPort.c_str(), dump.dstIp.c_str(), dump.dstPort.c_str());
	cout << "  Filename: " << dump.filename << endl;
	cout << "  Sent Packet Count     : " << dump.sentPacketCount << endl;
	cout << "  Received Packet Count : " << dump.recvPacketCount << endl;
	cout << "  ACK Count             : " << dump.ackCount << endl;
	cout << "  Sent Bytes Count      : " << dump.sentBytesCount << endl;
	cout << "  Max payload size      : " << dump.max_payload_size;
	if (dump.max_payload_size > 1460) {
		colored_printf(YELLOW, "   (Max payload for a packet is bigger than 1460. This may be caused by GSO/TSO (see readme))");
	}

	cout << endl;

	if (GlobOpts::withRecv) {
		map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
		long int ranges_count = 0;
		long int ranges_lost = 0;
		long int ranges_sent = 0;
		for (cIt = dump.conns.begin(); cIt != dump.conns.end(); cIt++) {
			ranges_count += cIt->second->rm->getByteRangesCount();
			ranges_sent += cIt->second->rm->getByteRangesSent();
			ranges_lost += cIt->second->rm->getByteRangesLost();
		}
		cout << "  Received Bytes        : " << dump.recvBytesCount << endl;
		if ((dump.sentPacketCount - dump.recvPacketCount) < 0) {
			colored_printf(YELLOW, "Negative loss values is probably caused by GSO/TSO on sender side (see readme)\n");
		}
		cout << "  Packets Lost          : " << (dump.sentPacketCount - dump.recvPacketCount) << endl;
		cout << "  Packet Loss           : " << ((double) (dump.sentPacketCount - dump.recvPacketCount) / dump.sentPacketCount) * 100 <<  " %" << endl;
		cout << "  Ranges Count          : " << (ranges_count) << endl;
		cout << "  Ranges Sent           : " << (ranges_sent) << endl;
		cout << "  Ranges Lost           : " << (ranges_lost) << endl;
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


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Statistics::printStatistics() {
	/* Initiate struct for aggregate stats */
	struct connStats cs, csAggregated;
	memset(&cs, 0, sizeof(struct connStats));
	memset(&csAggregated, 0, sizeof(struct connStats));

	csAggregated.rdb_byte_hits = 0;
	csAggregated.rdb_byte_misses = 0;
	csAggregated.rdb_bytes_sent = 0;

	AggrPacketStats psAggregated;

	vector<string> itt_fnames;
	itt_fnames.push_back("itt-all.dat");
	globStats->prefix_filenames(itt_fnames);
	ofstream itt_stream;
	itt_stream.open(itt_fnames[0].c_str(), ios::out);
	itt_stream << "# time (usec), itt (msec), payload_size (bytes)" << endl;

	// Print stats for each connection or aggregated
	map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> sortedConns;
	fillWithSortedConns(sortedConns);
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = sortedConns.begin(); cIt != sortedConns.end(); cIt++) {
		memset(&cs, 0, sizeof(struct connStats));
		cIt->second->addConnStats(&cs);
		cIt->second->addConnStats(&csAggregated);

		/* Initialize bs struct */
		PacketStats bs;

		if (!GlobOpts::aggOnly) {
			bs.init();
		}

		cIt->second->genBytesLatencyStats(&bs);

		writeITT(itt_stream, bs.sent_times);

		if (!GlobOpts::aggOnly) {
			colored_printf(YELLOW, "STATS FOR CONN: %s:%u -> %s:%u", cIt->second->getSrcIp().c_str(), cIt->second->srcPort,
			       cIt->second->getDstIp().c_str(), cIt->second->dstPort);

			if (GlobOpts::analyse_start || GlobOpts::analyse_end || GlobOpts::analyse_duration) {
				colored_printf(YELLOW, " (Interval alalysed (sec): %d-%d)", cIt->second->rm->analyse_time_sec_start, cIt->second->rm->analyse_time_sec_end);
			}
			printf("\n");
			printPacketStats(&cs);
			printPayloadStats(&bs);
		}

		if (!GlobOpts::aggOnly) {
			printBytesLatencyStatsConn(&bs);

			// ITT stats
			printPacketITTStats(&bs);
			print_stats_separator(true);
		}

		if (GlobOpts::aggregate) {
			psAggregated.add(bs);
		}
	}

	if (GlobOpts::aggregate) {
		if (csAggregated.nrPacketsSent) { /* To avoid division by 0 */
			csAggregated.duration /= sortedConns.size();

			cout << "\nAggregated Statistics for " << sortedConns.size() << " connections:" << endl;
			printPacketStats(&csAggregated);
			printPayloadStatsAggr(&csAggregated, psAggregated);

			/* Print Aggregate bytewise latency */
			printBytesLatencyStatsAggr(&csAggregated, psAggregated);

			// ITT stats
			printPacketITTStatsAggr(&csAggregated, psAggregated);
			print_stats_separator(true);
		}
	}
	itt_stream.close();
}


void printPayloadStats(PacketStats *ps) {
	printf("Payload size stats:\n");
	printStats("payload", "bytes", ps->packet_length);
	ps->packet_length._percentiles.print("P  %*sth percentile %-26s    : %10.0f\n");
}

void printPayloadStatsAggr(connStats *cs, AggrPacketStats &aggrStats) {
	printf("Payload size stats:\n");
	printStatsAggr("payload", "bytes", cs, aggrStats.aggregated.packet_length, aggrStats.minimum.packet_length,
				   aggrStats.average.packet_length, aggrStats.maximum.packet_length);
	aggrStats.aggregated.packet_length._percentiles.print("P  %*sth percentile %-26s    : %10.0f\n");
}

void printPacketITTStats(PacketStats* bs)
{
	print_stats_separator(false);
	printf("ITT stats:\n");
	printStats("itt", "ms", bs->itt);
	bs->itt._percentiles.print("  %*sth percentile %-26s    : %10.0f ms\n");
}

void printPacketITTStatsAggr(connStats *cs, AggrPacketStats &aggrStats)
{
	print_stats_separator(false);
	printf("ITT stats (Average for all the connections)\n");
	printStatsAggr("ITT", "ms", cs, aggrStats.aggregated.itt, aggrStats.minimum.itt, aggrStats.average.itt, aggrStats.maximum.itt);
	aggrStats.aggregated.itt._percentiles.print("  %*sth percentile %-26s    : %10.0f ms\n");
}


void printPacketStats(connStats *cs) {
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
	       "  Total bytes sent (payload)                    : %10lu\n"	\
	       "  Number of unique bytes                        : %10lu\n"   \
	       "  Number of retransmitted bytes                 : %10d\n"	\
		   "  Redundant bytes (bytes already sent)          : %10lu (%.2f %%)\n",
		   cs->pureAcksCount, syn_fin_rst,
		   cs->nrRetrans, cs->bundleCount, cs->nrRetrans - cs->nrRetransNoPayload + cs->bundleCount, cs->ackCount,
           (ulong)cs->totBytesSent,
	       (ulong)cs->totUniqueBytesSent, cs->totRetransBytesSent,
           (ulong)(cs->totBytesSent - cs->totUniqueBytesSent),
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

		printf("  Bytes Lost (actual loss on receiver side)     : %10lu\n", (ulong)cs->bytes_lost);
		printf("  Bytes Loss                                    : %10.2f %%\n", safe_div(cs->bytes_lost, cs->totBytesSent) * 100);
		printf("  Ranges Lost (actual loss on receiver side)    : %10lu\n", (ulong)cs->ranges_lost);
		printf("  Ranges Loss                                   : %10.2f %%\n", safe_div(cs->ranges_lost, cs->ranges_sent) * 100);
	}

	print_stats_separator(false);

	if (cs->rdb_bytes_sent) {
		print_stats_separator(false);
		printf("RDB stats:\n");
		printf("  RDB packets                                   : %10d (%.2f%% of data packets sent)\n", cs->bundleCount, safe_div(cs->bundleCount, cs->nrDataPacketsSent) * 100);
		printf("  RDB bytes bundled                             : %10lu (%.2f%% of total bytes sent)\n", (ulong)cs->rdb_bytes_sent, safe_div(cs->rdb_bytes_sent, cs->totBytesSent) * 100);

		if (GlobOpts::withRecv) {
			printf("  RDB packet hits                               : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_hits, safe_div(cs->rdb_packet_hits, cs->bundleCount) * 100);
			printf("  RDB packet misses                             : %10d (%.2f%% of RDB packets sent)\n", cs->rdb_packet_misses, safe_div(cs->rdb_packet_misses, cs->bundleCount) * 100);
			printf("  RDB byte hits                                 : %10lu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   (ulong)cs->rdb_byte_hits, safe_div(cs->rdb_byte_hits, cs->rdb_bytes_sent) * 100, safe_div(cs->rdb_byte_hits, cs->totBytesSent) * 100);
			printf("  RDB byte misses                               : %10lu (%.2f%% of RDB bytes, %.2f%% of total bytes)\n",
				   (ulong)cs->rdb_byte_misses, safe_div(cs->rdb_byte_misses, cs->rdb_bytes_sent) * 100, safe_div(cs->rdb_byte_misses, cs->totBytesSent) * 100);
		}
	}
}

void printStats(string prefix, string unit, BaseStats& bs) {
	printf("  Minimum %10s                            : %7lu %s\n", prefix.c_str(), (ulong)bs.min, unit.c_str());
	printf("  Average %10s                            : %7.0f %s\n", prefix.c_str(), bs.get_avg(), unit.c_str());
	printf("  Maximum %10s                            : %7lu %s\n", prefix.c_str(), (ulong)bs.max, unit.c_str());
}

void printStatsAggr(string prefix, string unit, connStats *cs, BaseStats& bs,
					BaseStats& aggregatedMin, BaseStats& aggregatedAvg, BaseStats& aggregatedMax) {
	if (aggregatedMin.min == (numeric_limits<int64_t>::max)())
		aggregatedMin.min = aggregatedMin.max = 0;

	printf("  Minimum %10s (min, avg, max)            :    %7lu, %7.0f, %7lu %s\n",
		   prefix.c_str(), (ulong)aggregatedMin.min, aggregatedMin.get_avg(), (ulong)aggregatedMin.max, unit.c_str());
	printf("  Average %10s (min, avg, max)            :    %7lu, %7.0f, %7lu %s\n",
		   prefix.c_str(), (ulong)aggregatedAvg.min, aggregatedAvg.get_avg(), (ulong)aggregatedAvg.max, unit.c_str());
	printf("  Maximum %10s (min, avg, max)            :    %7lu, %7.0f, %7lu %s\n",
		   prefix.c_str(), (ulong)aggregatedMax.min, aggregatedMax.get_avg(), (ulong)aggregatedMax.max, unit.c_str());
	printf("  Average of all packets in all connections     : %10d %s\n",
		   (int) floorf((double) safe_div(bs.cum, cs->nrDataPacketsSent)), unit.c_str());
}

void printBytesLatencyStatsAggr(connStats *cs, AggrPacketStats &aggrStats) {
	print_stats_separator(false);
	printf("Latency stats (Average for all the connections)\n");
	printStatsAggr("latencies", "ms", cs, aggrStats.aggregated.latency, aggrStats.minimum.latency,
				   aggrStats.average.latency, aggrStats.maximum.latency);

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
	printBytesLatencyStats(&aggrStats.aggregated);
}

void printBytesLatencyStatsConn(PacketStats* bs) {
	print_stats_separator(false);
	printf("Latency stats:\n");
	printStats("latency", "ms", bs->latency);
	printBytesLatencyStats(bs);
}

/* Print latency statistics */
void printBytesLatencyStats(PacketStats* bs) {

	bs->latency._percentiles.print("L %*sth percentile %-26s    : %10.0f ms\n");

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
		for (ulong i = 0; i < bs->retrans.size(); i++) {
			if ((GlobOpts::verbose < 2) && i > 2)
				break;
			if (bs->retrans[i] == 0)
				break;
			printf("  %2lu. retransmission (count / accumulated)      : %6d / %d\n", i+1, bs->retrans[i], retrans_accumed[i]);
		}
		print_stats_separator(false);

		vector<int> dupacks_accumed = bs->dupacks;
		for (value = 0, curr = dupacks_accumed.rbegin(); curr != dupacks_accumed.rend(); ++curr) {
			*curr += value;
			value = *curr;
		}
		printf("  Max dupacks                                   : %10lu \n", bs->dupacks.size());
		for (ulong i = 0; i < bs->dupacks.size(); i++) {
			if ((GlobOpts::verbose > 1) || i < 3)
				printf("  %2lu. dupacks (count / accumulated)             : %6d / %d\n", i+1, bs->dupacks[i], dupacks_accumed[i]);
			//printf("  Occurrences of %2lu. dupacks                   : %d\n", i + 1, bs->dupacks[i]);
		}
	}
}

void Statistics::writeByteLatencyVariationCDF() {
	ofstream cdf_f;
	stringstream cdffn;
	cdffn << GlobOpts::prefix << "latency-variation-cdf.dat";
	cdf_f.open((char*)((cdffn.str()).c_str()), ios::out);

	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = dump.conns.begin(); cIt != dump.conns.end(); cIt++) {
		cIt->second->writeByteLatencyVariationCDF(&cdf_f);
	}
	cdf_f.close();
}

void Statistics::writeAggByteLatencyVariationCDF() {
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


void Statistics::genAckLatencyFiles() {
	map<ConnectionMapKey*, Connection*>::iterator cIt = dump.conns.begin();

	const long first_ts = TV_TO_MS(dump.first_sent_time);

	for (cIt = dump.conns.begin(); cIt != dump.conns.end(); cIt++) {
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
        stream << "# Timestamp/ms, Latency/ms" << endl;
		it = GlobStats::ack_latency_vectors[i]->begin();
		it_end = GlobStats::ack_latency_vectors[i]->end();
		// Write the header
		if (it != it_end)
			stream << it->header() << endl;

		for (; it != it_end; it++) {
			stream << it->str() << endl;
		}
		stream.close();
	}

	ofstream stream;
	stream.open(filenames[i].c_str(), ios::out);
	// Handle duration data
	for (cIt = dump.conns.begin(); cIt != dump.conns.end(); cIt++) {
		stream << cIt->second->getDuration(true) << endl;
	}
	stream.close();
	i++;
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
void Statistics::write_loss_to_file() {
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
	for (conn = dump.conns.begin(); conn != dump.conns.end(); ++conn) {

		unique_ptr< vector<LossInterval> > loss(new vector<LossInterval>());

		conn->second->rm->calculateLossGroupedByInterval(TV_TO_MS(dump.first_sent_time), *aggr, *loss);
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


void Statistics::makeByteLatencyVariationCDF() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = dump.conns.begin(); cIt != dump.conns.end(); cIt++) {
		cIt->second->makeByteLatencyVariationCDF();
	}
}

void Statistics::writeSentTimesAndQueueingDelayVariance() {
	map<ConnectionMapKey*, Connection*>::iterator it;
	const uint64_t first_tstamp = TV_TO_MS(dump.first_sent_time);

	ofstream all_stream;
	all_stream.open((GlobOpts::prefix + "queueing-delay-all.dat").c_str(), ios::out);

	for (it = dump.conns.begin(); it != dump.conns.end(); ++it) {
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


void Statistics::writePacketByteCountAndITT() {
	map<ConnectionMapKey*, Connection*>::iterator it;

	ofstream* all_stream = NULL;
	ofstream* conn_stream = NULL;
	string header("timestamp,itt,payload_size,packet_size");

	if (GlobOpts::aggregate) {
		all_stream = new ofstream;
		all_stream->open((GlobOpts::prefix + "packet-byte-count-and-itt-all.dat").c_str(), ios::out);
		*all_stream << header << endl;
	}

	for (it = dump.conns.begin(); it != dump.conns.end(); ++it) {

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


/*
 * Writes number of bytes and packets sent aggregated over time slices to file (throughput)
 */
void Statistics::writeByteCountGroupedByInterval() {
	map<ConnectionMapKey*, Connection*>::iterator conn;

	if (GlobOpts::aggregate) {
		auto_ptr< vector< pair<uint64_t,uint64_t> > > all_sizes(new vector< pair<uint64_t,uint64_t> >);

		uint64_t idx, num;
		for (conn = dump.conns.begin(); conn != dump.conns.end(); conn++) {
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
		for (conn = dump.conns.begin(); conn != dump.conns.end(); conn++) {
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

void Statistics::writeITT(ofstream& stream, vector<SentTime>& sent_times) {
	for (size_t i = 0; i < sent_times.size(); i++) {
		stream << (sent_times[i].time) << "," << sent_times[i].itt << "," << sent_times[i].size << endl;
	}
}
