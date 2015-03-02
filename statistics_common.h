#ifndef STATISTICS_COMMON_H
#define STATISTICS_COMMON_H

#include "common.h"

// A loss value object, used for aggregating loss over intervals
struct LossInterval {
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
	void add_total(double ranges, double all_bytes, double new_bytes);
};
ofstream& operator<<(ofstream& ouput_stream, const LossInterval& value);


struct LatencyItem {
	long time_ms;
	int latency;
	string stream_id;
	LatencyItem(long time_ms, int latency, string stream_id)
		: time_ms(time_ms), latency(latency), stream_id(stream_id) { }

	string str() const;
	string header() { return "time,latency,stream_id"; }
	operator string() const { return str(); }
};
ofstream& operator<<(ofstream& stream, const LatencyItem& lat);

void update_vectors_size(vector<SPNS::shared_ptr<vector <LatencyItem> > > &vectors, ulong count);

class GlobStats
{
public:
	static map<const long, int> byteLatencyVariationCDFValues;
    static uint64_t totNumBytes;
};

/* Struct used to pass aggregated data between connections */
struct ConnStats {
public:
	int duration;
	int analysed_duration_sec; // The duration of the part that was analysed
	int analysed_start_sec; // The duration of the part that was analysed
	int analysed_end_sec; // The duration of the part that was analysed
	uint64_t totBytesSent;
	uint64_t bytes_lost;
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
	uint64_t totUniqueBytes;
	uint64_t totUniqueBytesSent;
	uint64_t redundantBytes;
	int rdb_packet_hits;
	int rdb_packet_misses;
	uint64_t rdb_bytes_sent;
	uint64_t rdb_byte_misses;
	uint64_t rdb_byte_hits;
	uint64_t ranges_sent;
	uint64_t ranges_lost;
};

struct Percentiles
{
	map<string, double> percentiles;
	int max_char_length;

	void init();
    void compute( const vector<double>& v );
	void print(string fmt, bool show_quartiles = true);
};

struct SentTime
{
	uint64_t time;
	uint16_t size;
	uint16_t itt;
	SentTime(uint64_t t, uint16_t s) : time(t), size(s), itt(0) {}

	bool operator < (const SentTime& other) const {
        return (time < other.time);
    }
};

class BaseStats
{
	bool _is_aggregate;
    int32_t _counter;
public:
	int64_t min;
	int64_t max;
	int64_t cum;
    bool    valid;

	BaseStats(bool is_aggregate);

    void add_to_aggregate( const BaseStats &rhs );

    // add to cum, increase _counter, update min and max
    void add( uint64_t );

    double   get_avg( ) const;
    uint32_t get_counter( ) const;
};

class ExtendedStats : public BaseStats
{
public:
    ExtendedStats(bool _is_aggregate = false)
        : BaseStats(_is_aggregate)
    { }

    void add_to_aggregate( const ExtendedStats &rhs );

    // call BaseStats::add, append to _values
    void add( uint64_t );

    // derive _std_dev and _percentiles from _values
    void makeStats( );
    void sortValues( );
    void computePercentiles( );

    Percentiles    _percentiles;
    double         _std_dev;

private:
    vector<double> _values;
};

class ExtendedPacketStats {
public:
	ExtendedStats latency;
	ExtendedStats packet_length;
	ExtendedStats itt;

	void init() {
		latency._percentiles.init();
		packet_length._percentiles.init();
		itt._percentiles.init();
	}
	ExtendedPacketStats(bool is_aggregate) :
		latency(is_aggregate),
		packet_length(is_aggregate),
		itt(is_aggregate)
	{}
};

/* Struct used to keep track of bytewise latency stats */
class PacketStats : public ExtendedPacketStats {
public:
	vector<SentTime> sent_times;
	vector<int> retrans;
	vector<int> dupacks;

	bool has_stats() {
		return latency.get_counter() > 0;
	}

	PacketStats(bool _is_aggregate = false) : ExtendedPacketStats(_is_aggregate) {}
};

class AggrPacketStats {
public:
	PacketStats aggregated;
	ExtendedPacketStats minimum;
	ExtendedPacketStats average;
	ExtendedPacketStats maximum;

	void init() {
		aggregated.init();
		minimum.init();
		maximum.init();
	}

	AggrPacketStats()
		: aggregated(true)
		, minimum(false)
		, average(false)
		, maximum(false) {
		init();
	}
	void add(PacketStats &bs);
};

#endif /* STATISTICS_COMMON_H */
