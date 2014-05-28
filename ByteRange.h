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

class ByteRange {
public:
	uint64_t startSeq;                 // The relative sequence number of the first byte in this range
	uint64_t endSeq;                   // The relative sequence number of the last byte in this range
	uint8_t received_count;            // Count number of times this byte range has been received
	uint8_t sent_count;                // Count number of times this byte range has been sent (incl. retransmissions)
	uint16_t byte_count;               // The number of bytes in this range
	uint16_t original_payload_size;
	uint8_t packet_sent_count;         // Count number of packet transmissions. This value is not copied when splitting a byte range!
	uint8_t packet_retrans_count;      // Count number of packet retransmissions. This value is not copied when splitting a byte range!
	uint8_t packet_received_count;
	uint8_t data_retrans_count;        // Count number of times this byte range has been retransmitted
	uint8_t rdb_count;                 // Count number of times this byte range has been transmitted as redundant (rdb) data
	uint8_t rdb_byte_miss;
	uint8_t rdb_byte_hits;

	timeval received_tstamp_pcap;
	//vector<timeval> sent_tstamp_pcap;  // pcap tstamp for regular packet and retrans
	vector< pair<timeval, uint8_t> > sent_tstamp_pcap;

	uint8_t send_tcp_stamp_recv_index; // The index of the element in the tstamps_tcp vector that matches the received tcp time stamp
	uint32_t received_tstamp_tcp;
	vector<uint32_t> tstamps_tcp;      // tcp tstamp for regular packet and retrans
	vector<uint32_t> rdb_tstamps_tcp;  // tcp tstamp for data in RDB packets
	vector< pair<uint32_t,timeval> > lost_tstamps_tcp; // tcp tstamp matched to recevied used to find which packets were lost

	struct timeval ackTime;
	uint8_t acked : 1,
		original_packet_is_rdb : 1,
		recv_type : 2,                 // DEF, DATA, RDB, RETR
		app_layer_latency_tstamp : 1;  // If application layer latency should use the receiver time stamp (1), or the stampt of previous range (0).
	uint8_t recv_type_num;             // Which packet of the specific type was first received
	uint8_t fin;
	uint8_t syn;
	uint8_t rst;
	uint8_t acked_sent;                // Count acks sent for this sequence number
	uint8_t ack_count;                 // Count number of times this packet was acked
	uint8_t dupack_count;
	uint16_t tcp_window;
	long diff;

	ByteRange(uint32_t start, uint32_t end) {
		startSeq = start;
		endSeq = end;
		sent_count = 0;
		byte_count = 0;
		received_count = 0;
		dupack_count = 0;
		acked = 0;
		ack_count = 0;
		send_tcp_stamp_recv_index = 0;
		update_byte_count();
		original_payload_size = byte_count;
		packet_sent_count = 0;
		packet_received_count = 0;
		packet_retrans_count = 0;
		data_retrans_count = 0;
		rdb_count = 0;
		recv_type = DEF;
		recv_type_num = 1;
		received_tstamp_tcp = 0;
		rdb_byte_miss = 0;
		rdb_byte_hits = 0;
		diff = 0;
		tcp_window = 0;
		ackTime.tv_sec = 0;
		ackTime.tv_usec = 0;
		fin = 0;
		syn = 0;
		rst = 0;
		original_packet_is_rdb = false;
		acked_sent = 0;
		app_layer_latency_tstamp = 0;
	}

	inline void increase_received(uint32_t tstamp_tcp, timeval tstamp_pcap, bool in_sequence) {
		if (!received_count) {
			app_layer_latency_tstamp = in_sequence;
			received_tstamp_tcp = tstamp_tcp;
			received_tstamp_pcap = tstamp_pcap;
		}
		received_count++;

		vector< pair<uint32_t,timeval> >::iterator it, it_end;
		it = lost_tstamps_tcp.begin(), it_end = lost_tstamps_tcp.end();
		while (it != it_end) {
			if (it->first == tstamp_tcp) {
				lost_tstamps_tcp.erase(it);
				break;
			}
			it++;
		}
	}

	inline void increase_sent(uint32_t tstamp_tcp, timeval tstamp_pcap, bool rdb, bool packet_sent=true) {
		if (rdb) {
			rdb_tstamps_tcp.push_back(tstamp_tcp);
		}
		else {
			tstamps_tcp.push_back(tstamp_tcp);
		}
		if (packet_sent)
			packet_sent_count++;

		sent_count++;
		sent_tstamp_pcap.push_back(pair<timeval, uint8_t>(tstamp_pcap, packet_sent));
		lost_tstamps_tcp.push_back(pair<uint32_t,timeval>(tstamp_tcp, tstamp_pcap));
	}

	void update_byte_count() {
		byte_count = endSeq - startSeq;
		if (endSeq != startSeq)
			byte_count += 1;
	}

	// Split and make a new range at the end
	ByteRange* split_end(uint64_t start, uint64_t end) {
		endSeq = start - 1;
		return split(start, end);
	}

/*
	// Split and make a new range at the beginning
	ByteRange* split_start(uint64_t start, uint64_t end) {
		startSeq = end + 1;
		return split(start, end);
	}
*/
	ByteRange* split(uint64_t start, uint64_t end) {
		ByteRange *new_br = new ByteRange(start, end);
		new_br->packet_sent_count = 0;
		new_br->data_retrans_count = data_retrans_count;
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

	bool match_received_type(bool print=false);
	void print_tstamps_tcp();

	uint64_t getStartSeq() { return startSeq; }
	uint64_t getEndSeq() { return endSeq; }
	int getSendAckTimeDiff(RangeManager *rm);
	int getNumRetrans() { return packet_retrans_count; }
	uint8_t getNumBundled() { return rdb_count; }
	uint16_t getNumBytes() { return byte_count; }
	int getOrinalPayloadSize() { return original_payload_size; }
	int getTotalBytesTransfered() { return byte_count + byte_count * data_retrans_count + byte_count * rdb_count; }
	bool isAcked() { return acked; }
	void insertAckTime(timeval *tv) { ackTime = *tv; acked = true; }
	void calculateRecvDiff(timeval *recv_tstamp = NULL);
	long getRecvDiff() { return diff; }
	void setRecvDiff(long diff) { this->diff = diff; }
	void printValues();
	void print_tstamps_pcap();
	timeval* getSendTime();
	timeval* getRecvTime();
	timeval* getAckTime();
	void setRecvTime(timeval *tv) { received_tstamp_pcap = *tv; }
};

double getTimeInterval(ByteRange *start, ByteRange *end);

#endif /* BYTERANGE_H */
