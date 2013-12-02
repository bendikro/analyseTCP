#ifndef BYTERANGE_H
#define BYTERANGE_H

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
#include "RangeManager.h"
#include "time_util.h"

enum received_type {DEF, DATA, RDB, RETR};
extern const char *received_type_str[4];

/* Modified timersub macro that has defined behaviour
   also for negative differences */
# define negtimersub(a, b, result)									\
	do {															\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;				\
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			\
		if ( (result)->tv_sec > 0) {								\
			if ((result)->tv_usec < 0) {							\
				--(result)->tv_sec;									\
				(result)->tv_usec += 1000000;						\
			}														\
		} else if ( (result)->tv_sec < 0 ) {						\
			if ((result)->tv_usec > 0) {							\
				++(result)->tv_sec;									\
				(result)->tv_usec = 1000000 - (result)->tv_usec;	\
			} else { /* if (tv_usec < 0) */							\
				(result)->tv_usec *= -1;							\
			}														\
			if((result)->tv_sec == 0 )								\
				(result)->tv_usec *= -1;							\
		}															\
	} while (0)

class ByteRange {
public:
	uint64_t startSeq;
	uint64_t endSeq;
	int received_count;
	int sent_count;
	int byte_count;
	int original_payload_size;
	int retrans_count;

	int rdb_count;
	int rdb_byte_miss;
	int rdb_byte_hits;
	received_type recv_type; // 0 == first transfer, 1 == RDB, 2 == retrans
	int recv_type_num; // Which packet of the specific type was first received

	timeval received_tstamp_pcap;
	uint32_t received_tstamp_tcp;

	vector<timeval> sent_tstamp_pcap;  // pcap tstamp for regular packet and retrans

	vector<uint32_t> tstamps_tcp;      // tcp tstamp for regular packet and retrans
	vector<uint32_t> rdb_tstamps_tcp;  // tcp tstamp for data in RDB packets
	vector<uint32_t> lost_tstamps_tcp; // tcp tstamp matched to recevied used to find which packets were lost

	struct timeval ackTime;
	unsigned int acked : 1;
	u_short tcp_window;
	int dupack_count;

	long diff, dcDiff;

	ByteRange(uint32_t start, uint32_t end) {
		startSeq = start;
		endSeq = end;
		sent_count = 0;
		received_count = 0;
		dupack_count = 0;
		acked = 0;
		update_byte_count();
		retrans_count = 0;
		rdb_count = 0;
		recv_type = DEF;
		recv_type_num = 1;
		received_tstamp_tcp = 0;
		rdb_byte_miss = 0;
		rdb_byte_hits = 0;
		diff = 0;
		dcDiff = 0;
		tcp_window = 0;
		ackTime.tv_sec = 0;
		ackTime.tv_usec = 0;
	}

	inline void increase_received(uint32_t tstamp_tcp, timeval tstamp_pcap) {
		if (!received_count) {
			received_tstamp_tcp = tstamp_tcp;
			received_tstamp_pcap = tstamp_pcap;
		}
		received_count++;

		vector<uint32_t>::iterator it, it_end;
		it = lost_tstamps_tcp.begin(), it_end = lost_tstamps_tcp.end();
		while (it != it_end) {
			if (*it == tstamp_tcp) {
				lost_tstamps_tcp.erase(it);
				break;
			}
			it++;
		}
	}

	inline void increase_sent(uint32_t tstamp_tcp, timeval tstamp_pcap, bool rdb) {
		if (rdb) {
			rdb_tstamps_tcp.push_back(tstamp_tcp);
		}
		else {
			tstamps_tcp.push_back(tstamp_tcp);
		}
		sent_count++;
		sent_tstamp_pcap.push_back(tstamp_pcap);
		lost_tstamps_tcp.push_back(tstamp_tcp);
	}

	void update_byte_count() {
		byte_count = endSeq - startSeq;
		if (endSeq != startSeq)
			byte_count += 1;
		original_payload_size = byte_count;
	}

	// Split and make a new range at the end
	ByteRange* split_end(uint64_t start, uint64_t end) {
		endSeq = start - 1;
		return split(start, end);
	}

	// Split and make a new range at the beginning
	ByteRange* split_start(uint64_t start, uint64_t end) {
		startSeq = end + 1;
		return split(start, end);
	}
	ByteRange* split(uint64_t start, uint64_t end) {
		ByteRange *new_br = new ByteRange(start, end);
		new_br->retrans_count = retrans_count;
		new_br->sent_count = sent_count;
		new_br->received_count = received_count;
		new_br->sent_tstamp_pcap = sent_tstamp_pcap;
		new_br->received_tstamp_tcp = received_tstamp_tcp;
		new_br->tstamps_tcp = tstamps_tcp;
		new_br->rdb_tstamps_tcp = rdb_tstamps_tcp;
		new_br->ackTime = ackTime;
		new_br->acked = acked;
		update_byte_count();
		return new_br;
	}

	bool match_received_type();
	bool match_received_type(bool print);
	void print_tstamps_tcp();

	uint64_t getStartSeq() { return startSeq; }
	uint64_t getEndSeq() { return endSeq; }
	int getSendAckTimeDiff(RangeManager *rm);
	int getNumRetrans() { return retrans_count; }
	int getNumBundled() { return rdb_count; }
	int getNumBytes() { return byte_count; }
	int getOrinalPayloadSize() { return original_payload_size; }
	int getTotalBytesTransfered() { return byte_count + byte_count * retrans_count + byte_count * rdb_count; }
	bool isAcked() { return acked; }
	void insertAckTime(timeval *tv) { ackTime = *tv; acked = true; }

	void setDiff();
	void setDcDiff(long diff) { dcDiff = diff;}
	long getDcDiff() { return dcDiff;}
	long getRecvDiff() { return diff; }
	void printValues();
	void print_tstamps_pcap();
	timeval* getSendTime();
	timeval* getRecvTime();
	timeval* getAckTime();
	void setRecvTime(timeval *tv) { received_tstamp_pcap = *tv; }
};

#endif /* BYTERANGE_H */
