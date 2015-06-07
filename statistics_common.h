#ifndef STATISTICS_COMMON_H
#define STATISTICS_COMMON_H

#include "common.h"
#include "minicsv.h"

// A loss value object, used for aggregating loss over intervals
class  LossInterval {
public:
	double cnt_bytes;		// number of ranges lost within interval
	double all_bytes;		// number of bytes (incl. retrans) lost within interval
	double new_bytes;		// number of bytes with new data lost within interval
	double tot_cnt_bytes;	// total number of ranges sent within interval
	double tot_all_bytes;	// total number of bytes sent within interval
	double tot_new_bytes;	// total number of bytes sent with new data within interval

	LossInterval(double ranges, double all_bytes, double new_bytes)
		: cnt_bytes(ranges), all_bytes(all_bytes), new_bytes(new_bytes)
		, tot_cnt_bytes(0), tot_all_bytes(0), tot_new_bytes(0)
	{ }

	LossInterval& operator+=(const LossInterval& rhs);
	static void writeHeader(csv::ofstream& stream);
	void addTotal(double ranges, double all_bytes, double new_bytes);

};
csv::ofstream& operator<<(csv::ofstream& stream, LossInterval& v);


class LatencyItem {
public:
	long time_ms;
	int latency;
	string stream_id;
	LatencyItem(long time_ms, int latency, string stream_id)
		: time_ms(time_ms), latency(latency), stream_id(stream_id) { }

	static void writeHeader(csv::ofstream& stream) {
		stream << "time" << "latency" << "stream_id" << NEWLINE;
	}
};
csv::ofstream& operator<<(csv::ofstream& stream, LatencyItem& lat);

void update_vectors_size(vector<SPNS::shared_ptr<vector <LatencyItem> > > &vectors, ulong count);

class GlobStats
{
public:
	static map<const long, int> byteLatencyVariationCDFValues;
	static ullint_t totNumBytes;
};

/* Struct used to pass aggregated data between connections */
struct ConnStats {
public:
	int duration;
	int analysed_duration_sec; // The duration of the part that was analysed
	int analysed_start_sec; // The duration of the part that was analysed
	int analysed_end_sec; // The duration of the part that was analysed
	ullint_t totBytesSent;
	ullint_t totUniqueBytes;
	ullint_t totUniqueBytesSent;
	ullint_t redundantBytes;
	ullint_t bytes_lost;
	int totRetransBytesSent;
	int totPacketSize;
	int nrDataPacketsSent;
	int nrPacketsSent;
	int nrPacketsSentFoundInDump; // This is the number of packets saved in the trace dump.
	                              // This might differ from actual packets on the wire because TCP segmentation offloading
	int nrPacketsReceivedFoundInDump;
	int nrRetrans;
	int nrRetransNoPayload;
	int bundleCount;
	int ackCount;
	int synCount;
	int finCount;
	int rstCount;
	int pureAcksCount;
	int rdb_packet_hits;
	int rdb_packet_misses;
	ullint_t rdb_bytes_sent;
	ullint_t rdb_byte_misses;
	ullint_t rdb_byte_hits;
	ullint_t ranges_sent;
	ullint_t ranges_lost;
};

struct Percentiles
{
	map<string, double> percentiles;
	int max_char_length;

	void init();
	void compute(const vector<double>& v);
	void print(string fmt, bool show_quartiles = true);
};

class BaseStats
{
#ifdef DEBUG
	bool _is_aggregate;
#endif
	int32_t _counter;
public:
	ullint_t min;
	ullint_t max;
	ullint_t cum;
	bool	valid;

	BaseStats()
#ifdef DEBUG
		: _is_aggregate(false)
#endif
{}
    BaseStats(bool is_aggregate) :
#ifdef DEBUG
		_is_aggregate(is_aggregate),
#endif
		_counter(0)
		, valid(true)
	{init();}


	void init();

	// add to cum, increase _counter, update min and max
	void add(ullint_t);
	void add_to_aggregate(const BaseStats &rhs);
	double get_avg() const;
	uint32_t get_counter() const;

	Percentiles	   _percentiles;
	double		   _std_dev;

	// derive _std_dev and _percentiles from _values
	void makeStats();
	void sortValues();
	void computePercentiles();

private:
	vector<double> _values;
};


class StreamStats {
public:
	BaseStats latency;
	BaseStats packet_length;
	BaseStats itt;

	void init() {
		latency.init();
		packet_length.init();
		itt.init();
	}
	StreamStats(bool is_aggregate) :
		latency(is_aggregate),
		packet_length(is_aggregate),
		itt(is_aggregate)
	{}
};

class PacketStats
{
public:
	sent_type s_type;
	string stream_id;
	uint64_t send_time_us;
	uint16_t size;
	uint16_t itt;
	int ack_latency_usec;
	PacketStats() {}
	PacketStats(sent_type type, string connKey, uint64_t time, uint16_t s)
		: s_type(type), stream_id(connKey), send_time_us(time), size(s), itt(0)
	{}
	static void writeHeader(csv::ofstream& stream);

	bool operator<(const PacketStats& other) const {
		return (send_time_us < other.send_time_us);
	}
};

csv::ofstream& operator<<(csv::ofstream& stream, PacketStats& s);

class SegmentStats : public PacketStats
{
public:
	vector< pair<int, int> > sojourn_times; // byte count, sojourn time

	SegmentStats() {}
	SegmentStats(sent_type type, string connKey, uint64_t time, uint16_t s)
		: PacketStats(type, connKey, time, s)
	{}
	static void writeHeader(csv::ofstream& stream);
};

csv::ofstream& operator<<(csv::ofstream& stream, SegmentStats& s);

/*
  Used only for producing statistics for terminal output
*/
class PacketsStats : public StreamStats {
public:
	vector<SegmentStats> packet_stats;
	vector<int> retrans;
	vector<int> dupacks;

	void init() {
		packet_stats.clear();
		retrans.clear();
		dupacks.clear();
		StreamStats::init();
	}

	void addPacketStats(SegmentStats &ps) {
		packet_stats.push_back(ps);
	}

	bool has_stats() {
		return latency.get_counter() > 0;
	}

	PacketsStats(bool _is_aggregate = false) : StreamStats(_is_aggregate) {}
};


/*
  Used only for producing statistics for terminal output
*/
class AggrPacketsStats {
public:
	PacketsStats aggregated;
	StreamStats minimum;
	StreamStats average;
	StreamStats maximum;

	void init() {
		aggregated.init();
		minimum.init();
		average.init();
		maximum.init();
	}

	AggrPacketsStats()
		: aggregated(true)
		, minimum(false)
		, average(false)
		, maximum(false) {
		init();
	}
	void add(PacketsStats &bs);
};


/* Forward declarations */
class Connection;

class ConnCSVItem {
public:
	Connection *conn;
	ConnStats *cs;
	PacketsStats *ps;

	ConnCSVItem(Connection &c, ConnStats &cstats, PacketsStats &p) : conn(&c), cs(&cstats), ps(&p) {}
	static void writeHeader(csv::ofstream& stream);

};
csv::ofstream& operator<<(csv::ofstream& stream, ConnCSVItem& val);


#endif /* STATISTICS_COMMON_H */
