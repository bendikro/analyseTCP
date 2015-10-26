#ifndef STATISTICS_H
#define STATISTICS_H

#include "minicsv.h"

class Dump;
class Connection;

class StatsWriter
{
public:
	// pure virtual function providing interface framework.
	virtual void begin() = 0;
	virtual void end() = 0;
	virtual void writeStats(Connection &conn) = 0;
	virtual string getConnFilename(Connection &conn) = 0;
	virtual string getAggrFilename() = 0;
	virtual bool getWriteHeader() = 0;
	virtual string getHeader() = 0;
	virtual void writeHeader(csv::ofstream& csv) = 0;
};

class StatsWriterBase : public StatsWriter
{
public:
	bool write_header;
	string header;
	string aggrPostfix;
	string filenameID;
	virtual bool getWriteHeader() { return write_header; }
	virtual string getHeader() { return header; }
	virtual void writeHeader(csv::ofstream& stream) { stream << getHeader() <<  NEWLINE; }

	virtual string getAggrFilename() {
		return GlobOpts::prefix + filenameID + aggrPostfix;
	}
	virtual string getConnFilename(Connection &conn) {
		return GlobOpts::prefix + filenameID + "-" + conn.getConnKey() + ".dat";
	}

	csv::ofstream* newOutStream(string filename) {
        csv::ofstream* stream = new csv::ofstream(filename);
		if (getWriteHeader())
			writeHeader(*stream);
		return stream;
	}

	void setHeader(string hdr) {
		header = hdr;
		write_header = true;
	};
	void setFilenameID(string id) {
		filenameID = id;
	};
	StatsWriterBase() :
		write_header(false),
		aggrPostfix("-aggr.dat")
	{}
};

class AggrStatsWriterBase : public StatsWriterBase
{
public:
	csv::ofstream* stream;
	virtual void begin() {
		stream = newOutStream(getAggrFilename());
	}
	virtual void end() {
		delete stream;
	}
};

class StreamStatsWriterBase : public StatsWriterBase
{
public:
	csv::ofstream* aggrStream;
	virtual void statsFunc(Connection &conn, vector<csv::ofstream*> streams) = 0;

	virtual void begin() {
		if (GlobOpts::aggregate) {
			aggrStream = newOutStream(getAggrFilename());
		}
	}
	virtual void end() {
		if (GlobOpts::aggregate) {
			delete aggrStream;
		}
	}

	virtual void writeStats(Connection &conn) {
		vector<csv::ofstream*> streams;
		csv::ofstream* connStream;
		if (GlobOpts::aggregate) {
			streams.push_back(aggrStream);
		}
		if (!GlobOpts::aggOnly) {
			connStream = newOutStream(getConnFilename(conn));
			streams.push_back(connStream);
		}
		statsFunc(conn, streams);
		if (!GlobOpts::aggOnly) {
			delete connStream;
		}
	}
};


class Statistics {
	Dump &dump;
public:
	void fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns);

	void printDumpStats();
	void printConns();
	void printStatistics();

	void makeByteLatencyVariationCDF();

	void writePacketByteCountAndITT();
	void writeAckLatency();
	void writeByteLatencyVariationCDF();
	void writeAggByteLatencyVariationCDF();
	void writeSentTimesAndQueueingDelayVariance();
	void writeByteCountGroupedByInterval(); // throughput

	void writeStatisticsFiles(StatsWriter &conf);
	void writeConnStats();
	void writeLossStats();
	void writePerPacketStats();
	void writePerSegmentStats();

	Statistics(Dump &d);
};

void printStatsAggr(string prefix, string unit, ConnStats *cs, BaseStats& bs, BaseStats& aggregatedMin,
					BaseStats& aggregatedAvg, BaseStats& aggregatedMax);
void printBytesLatencyStatsAggr(ConnStats *cs, AggrPacketsStats &aggrStats);
void printBytesLatencyStatsConn(PacketsStats* bs);
void printBytesLatencyStats(PacketsStats* bs);
void printPayloadStats(PacketsStats *ps);
void printPayloadStatsAggr(ConnStats *cs, AggrPacketsStats &aggrStats);
void printPacketsStats(ConnStats *cs);
void printPacketITTStats(PacketsStats* bs);
void printPacketITTStatsAggr(ConnStats *cs, AggrPacketsStats &aggrStats);
void printAggStats(string prefix, string unit, ConnStats *cs, BaseStats& bs, BaseStats& aggregatedMin, BaseStats& aggregatedMax);
void printStats(string prefix, string unit, BaseStats& bs);

#endif /* STATISTICS_H */
