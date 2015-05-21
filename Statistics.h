#ifndef STATISTICS_H
#define STATISTICS_H

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

	virtual string getAggrFilename() {
		return GlobOpts::prefix + filenameID + aggrPostfix;
	}
	virtual string getConnFilename(Connection &conn) {
		return GlobOpts::prefix + filenameID + "-" + conn.getConnKey() + ".dat";
	}

	ofstream* newStream(string filename) {
		ofstream* stream = new ofstream;
		stream->open(filename.c_str(), ios::out);
		if (getWriteHeader())
			*stream << getHeader() << endl;
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


class StreamStatsWriterBase : public StatsWriterBase
{
public:
	ofstream* aggrStream;
	virtual void statsFunc(Connection &conn, vector<ofstream*> streams) = 0;

	virtual void begin() {
		if (GlobOpts::aggregate) {
			aggrStream = newStream(getAggrFilename());
		}
	}
	virtual void end() {
		if (GlobOpts::aggregate) {
			delete aggrStream;
		}
	}

	virtual void writeStats(Connection &conn) {
		vector<ofstream*> streams;
		ofstream* connStream;
		if (GlobOpts::aggregate) {
			streams.push_back(aggrStream);
		}
		if (!GlobOpts::aggOnly) {
			connStream = newStream(getConnFilename(conn));
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

	void genAckLatencyFiles();
	void writePacketByteCountAndITT();
	void writeAckLatency();
	void write_loss_to_file();
	void writeITT(ofstream& stream, vector<PacketStats>& sent_times);
	void writeByteLatencyVariationCDF();
	void writeAggByteLatencyVariationCDF();
	void writeSentTimesAndQueueingDelayVariance();
	void writeByteCountGroupedByInterval(); // throughput

	void writeStatisticsFiles(StatsWriter &conf);
	void writeStatisticsFiles2(StatsWriter &conf);
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
