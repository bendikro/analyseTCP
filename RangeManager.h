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
class ByteRange;
class Connection;

/* Has responsibility for managing ranges, creating,
   inserting and resizing ranges as sent packets and ACKs
   are received */
class RangeManager {
 private:
	uint32_t lastContinuous; /* Last seq in sequence of ranges without gaps */
	uint32_t largestEndSeq;
	struct timeval highestRecvd;
	int  nrRanges;
	int redundantBytes;
	long lowestDiff; /* Used to create CDF. */
	long lowestDcDiff; /* Lowest diff when compensated for clock drift */
	float drift; /* Clock drift (ms/s) */

	int minimum_segment_size;
	int maximum_segment_size;

	multimap<ulong, ByteRange*>::iterator highestAckedByteRangeIt;
	vector<struct DataSeg*> recvd;
	vector<struct ByteRange*> recvd_bytes;
	map<const long, int> cdf;
	map<const int, int> dcCdf;
public:
	multimap<ulong, ByteRange*> ranges;
	ulong firstSeq; /* Global start seq */
	ulong lastSeq;  /* Global end seq */

	// The number of RDB bytes that were redundant and not
	int rdb_packet_misses;
	int rdb_packet_hits;
	int rdb_byte_miss;
	int rdb_byte_hits;
	int rdb_stats_available;
	int lost_ranges_count;
	int sent_ranges_count;
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
		highestAckedByteRangeIt = ranges.end();
		memset(&highestRecvd, 0, sizeof(highestRecvd));
		nrRanges = 0;
		redundantBytes = 0;
		rdb_byte_miss = 0;
		rdb_byte_hits = 0;
		rdb_packet_misses = 0;
		rdb_packet_hits = 0;
		rdb_stats_available = 0;
		lost_ranges_count = 0;
		sent_ranges_count = 0;
		lost_bytes = 0;
		max_seq = ULONG_MAX;
	};

	~RangeManager();

	void insertSentRange(struct sendData *sd);
	void insertRecvRange(struct sendData *sd);
	bool processAck(ulong ack, timeval* tv);
	void genStats(struct byteStats* bs);
	ByteRange* getLastRange() {
		multimap<ulong, ByteRange*>::reverse_iterator last = ranges.rbegin();
		return last->second;
	}
	ByteRange* getHighestAcked();
	int getTimeInterval(ByteRange *r);
	uint32_t getDuration();
	void validateContent();
	void registerRecvDiffs();
	void registerRecvDiffs2();
	void makeCdf();
	void writeCDF(ofstream *stream);
	void writeDcCdf(ofstream *stream);
	int calcDrift();
	int calcDrift2();
	void registerDcDiffs();
	void insert_byte_range(ulong start_seq, ulong end_seq, bool sent, struct DataSeg *data_seq, int level);
	void makeDcCdf();
	void genRFiles(string connKey);
	void free_recv_vector();
	int getNumBytes() { return lastSeq; } // lastSeq is the last relative seq number
	long int getByteRangesCount() { return ranges.size(); }
	long int getByteRangesLost() { return lost_ranges_count; }
	long int getByteRangesSent() { return sent_ranges_count; }
	int getRedundantBytes(){ return redundantBytes; }
	ulong relative_seq(ulong seq);
	bool hasReceiveData();
	void calculateRDBStats();
	void calculateRetransAndRDBStats();
	void write_loss_over_time(unsigned slice_interval, unsigned timeslice_count, FILE *loss_retrans_out, FILE *loss_loss_out);
	void printPacketDetails();
};


#endif /* RANGEMANAGER_H */
