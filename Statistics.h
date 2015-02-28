#ifndef STATISTICS_H
#define STATISTICS_H

class Dump;

class Statistics {
	Dump &dump;
public:
	void fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns);

	void printDumpStats();
	void printConns();
	void printStatistics();

	void makeByteLatencyVariationCDF();

	void genAckLatencyFiles();
	void writePacketByteCountAndITT();
	void write_loss_to_file();
	void writeITT(ofstream& stream, vector<SentTime>& sent_times);
	void writeByteLatencyVariationCDF();
	void writeAggByteLatencyVariationCDF();
	void writeSentTimesAndQueueingDelayVariance();
	void writeByteCountGroupedByInterval(); // throughput

	Statistics(Dump &d);
};

void printStatsAggr(string prefix, string unit, connStats *cs, BaseStats& bs, BaseStats& aggregatedMin,
					BaseStats& aggregatedAvg, BaseStats& aggregatedMax);
void printBytesLatencyStatsAggr(connStats *cs, AggrPacketStats &aggrStats);
void printBytesLatencyStatsConn(PacketStats* bs);
void printBytesLatencyStats(PacketStats* bs);
void printPayloadStats(PacketStats *ps);
void printPayloadStatsAggr(connStats *cs, AggrPacketStats &aggrStats);
void printPacketStats(connStats *cs);
void printPacketITTStats(PacketStats* bs);
void printPacketITTStatsAggr(connStats *cs, AggrPacketStats &aggrStats);
void printAggStats(string prefix, string unit, connStats *cs, BaseStats& bs, BaseStats& aggregatedMin, BaseStats& aggregatedMax);
void printStats(string prefix, string unit, BaseStats& bs);

#endif /* STATISTICS_H */
