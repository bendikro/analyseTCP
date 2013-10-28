#ifndef RANGEMANAGER_H
#define RANGEMANAGER_H

using namespace std;

#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <limits.h>
#include <map>
#include "Range.h"
#include "Connection.h"
#include <deque>
#include <algorithm>

/* Forward declarations */
class Range;
class Connection;

struct recvData {
	u_long startSeq;
	u_long endSeq;
	struct timeval tv;
	u_char *data;
	uint32_t payload_len;
};

struct sortByStartSeq {
  bool operator()(const struct recvData &x, const struct recvData &y){
    return x.startSeq < y.startSeq;
  }
};

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
	vector<struct recvData*> recvd;
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
	Connection *conn;

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
	};

	~RangeManager();

	Range* insertSentRange(struct sendData *sd);
	void insertRecvRange(struct sendData *sd);
	bool processAck(ulong ack, timeval* tv);
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
	void insert_byte_range(ulong start_seq, ulong end_seq, int sent, bool retrans, bool is_rdb, int level);
	void makeDcCdf();
	void genRFiles(string connKey);
	void free_recv_vector();
	int getNumBytes() { return lastSeq - firstSeq; }
	int getNrDummy() { return nrDummy; }
	int getRedundantBytes(){ return redundantBytes; }
	ulong relative_seq(ulong seq);
	bool hasReceiveData();
	void calculateRDBStats();
};

class ByteRange {
public:
	ulong startSeq;
	ulong endSeq;
	int received_count;
	int sent_count;
	int byte_count;
	int retrans;
	int is_rdb;
	int split_after_sent;

	ByteRange(uint32_t start, uint32_t end) {
		startSeq = start;
		endSeq = end;
		sent_count = 0;
		received_count = 0;
		split_after_sent = 0;
		byte_count = end - start;
		if (end != start)
			byte_count += +1;
		retrans = 0;
		is_rdb = 0;
	}
};

#endif /* RANGEMANAGER_H */
