#ifndef RANGEMANAGER_H
#define RANGEMANAGER_H

using namespace std;

#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <limits.h>
#include <map>
#include <deque>
#include <algorithm>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "analyseTCP.h"
#include "time_util.h"

/* Forward declarations */
class Range;
class ByteRange;
class Connection;

/*
struct recvData {
	u_long startSeq;
	u_long endSeq;
	struct timeval tv;
	u_char *data;
	uint32_t payload_len;
};
*/

/*
struct sortByStartSeq {
  bool operator()(const struct DataSeg &x, const struct DataSeg &y){
    return x.startSeq < y.startSeq;
  }
};
*/
/* Has responsibility for managing ranges, creating,
   inserting and resizing ranges as sent packets and ACKs
   are received */
class RangeManager {
 private:
	uint32_t lastContinuous; /* Last seq in sequence of ranges without gaps */
	uint32_t largestEndSeq;
	struct timeval highestRecvd;
	int  nrRanges;
	int nrDummy;
	int redundantBytes;
	int delBytes;
	long lowestDiff; /* Used to create CDF. */
	long lowestDcDiff; /* Lowest diff when compensated for clock drift */
	float drift; /* Clock drift (ms/s) */

	int minimum_segment_size;
	int maximum_segment_size;

	multimap<ulong, Range*>::iterator highestAckedIt;
	multimap<ulong, ByteRange*>::iterator highestAckedByteRangeIt;
	vector<struct DataSeg*> recvd;
	vector<struct ByteRange*> recvd_bytes;
	map<const int, int> cdf;
	map<const int, int> dcCdf;
	multimap<ulong, ByteRange*> brMap;
public:
	multimap<ulong, Range*> ranges;
	ulong firstSeq; /* Global start seq */
	ulong lastSeq;  /* Global end seq */

	// The number of RDB bytes that were redundant and not
	int rdb_packet_misses;
	int rdb_packet_hits;
	int rdb_byte_miss;
	int rdb_byte_hits;
	int rdb_stats_available;
	int lost_range_count;
	int lost_bytes;

	Connection *conn;
	ulong max_seq;
public:
	RangeManager(Connection *c, uint32_t first_seq) {
		conn = c;
		firstSeq = first_seq;
		largestEndSeq = 0;
		lastSeq = 0;
		lastContinuous = 0;
		lowestDiff = LONG_MAX;
		lowestDcDiff = LONG_MAX;
		highestAckedIt = ranges.end();
		highestAckedByteRangeIt = brMap.end();
		memset(&highestRecvd, 0, sizeof(highestRecvd));
		nrRanges = 0;
		nrDummy = 0;
		redundantBytes = 0;
		delBytes = 0;
		rdb_byte_miss = 0;
		rdb_byte_hits = 0;
		rdb_packet_misses = 0;
		rdb_packet_hits = 0;
		rdb_stats_available = 0;
		lost_range_count = 0;
		lost_bytes = 0;
		max_seq = ULONG_MAX;
	};

	~RangeManager();

	Range* insertSentRange(struct sendData *sd);
	void insertRecvRange(struct sendData *sd);
	bool processAck(ulong ack, timeval* tv);
	bool processAckByteRange(ulong ack, timeval* tv);
	void genStats(struct byteStats* bs);
	Range* getLastRange() {
		multimap<ulong, Range*>::reverse_iterator last = ranges.rbegin();
		return last->second;
	}
	Range* getHighestAcked();
	int getTotNumBytes() { return lastSeq - firstSeq - delBytes; }
	int getTimeInterval(Range *r);
	uint32_t getDuration();
	void validateContent();
	void registerRecvDiffs();
	void makeCdf();
	void printCDF(ofstream *stream);
	void printDcCdf(ofstream *stream);
	int calcDrift();
	void registerDcDiffs();
	void insert_byte_range(ulong start_seq, ulong end_seq, bool sent, struct DataSeg *data_seq, int level);
	void makeDcCdf();
	void genRFiles(string connKey);
	void free_recv_vector();
	int getNumBytes() { return lastSeq - firstSeq; }
	int getNrDummy() { return nrDummy; }
	long int getByteRangesCount() { return brMap.size(); }
	long int getByteRangesLost() { return lost_range_count; }
	int getRedundantBytes(){ return redundantBytes; }
	ulong relative_seq(ulong seq);
	bool hasReceiveData();
	void calculateRDBStats();
	void calculateRetransAndRDBStats();
	void write_loss_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *out_stream);
	void write_retrans_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *out_stream);
};


#endif /* RANGEMANAGER_H */
