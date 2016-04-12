#ifndef BYTERANGE_H
#define BYTERANGE_H

#include "RangeManager.h"
#include "common.h"
#include "time_util.h"

using namespace std;

# define END_SEQ(seq_end) (seq_end)

class ByteRange {
public:
	seq64_t startSeq;                  // The relative sequence number of the first byte in this range
	seq64_t endSeq;                    // The relative sequence number of the last byte in this range
	uint16_t byte_count;               // The number of bytes in this range
	uint16_t original_payload_size;
	uint8_t packet_sent_count;         // Count number of packet transmissions. This value is not copied when splitting a byte range!
	uint8_t packet_retrans_count;      // Count number of packet retransmissions. This value is not copied when splitting a byte range!
	uint8_t packet_received_count;
	uint8_t data_received_count;       // Count number of times this byte range has been received
	uint8_t data_sent_count;           // Count number of times this byte range has been sent (incl. retransmissions)
	uint8_t data_retrans_count;        // Count number of times this byte range has been retransmitted
	uint8_t rdb_count;                 // Count number of times this byte range has been transmitted as redundant (rdb) data
	uint8_t rdb_miss_count;
	uint8_t rdb_hit_count;

	vector< pair<seq64_t, timeval> > sojourn_tstamps; // endseq for segment, tstamp when entered kernel
	vector< pair<timeval, sent_type> > sent_tstamp_pcap; // pcap tstamp for when packet was sent, sent_type {ST_NONE, ST_PKT, ST_RTR, ST_PURE_ACK};
	timeval received_tstamp_pcap;
	uint8_t send_tcp_stamp_recv_index; // The index of the element in the tstamps_tcp vector that matches the received tcp time stamp
	uint32_t received_tstamp_tcp;
	vector< pair<uint32_t, uint32_t> > tstamps_tcp;
	vector< uint32_t> rdb_tstamps_tcp;  // tcp tstamp for data in RDB packets
	vector< vector< pair<seq64_t, seq64_t> > > tcp_sacks;  // tcp tstamp for data in RDB packets

	vector< pair<uint32_t, timeval> > lost_tstamps_tcp; // tcp tstamp matched to received used to find which packets were lost

	timeval ackTime;
	uint8_t acked : 1,
		original_packet_is_rdb : 1,
		recv_type : 2,                 // DEF, DATA, RDB, RETR
		sojourn_time : 1,              // If sojourn time can be calulcated
		app_layer_latency_tstamp : 1;  // If application layer latency should use the receiver time stamp (1), or the tstamp of previous range (0).
	uint8_t recv_type_num;             // Which packet of the specific type was first received
	int16_t sent_data_pkt_pcap_index;  // Index of the first transmission (ST_PKT) in the sent_tstamp_pcap vector
	uint8_t fin;                       // Number of FINs sent
	uint8_t syn;                       // Number of SYNs sent
	uint8_t rst;                       // Number of RSTs sent
	uint8_t acked_sent;                // Count acks sent for this sequence number
	uint8_t ack_count;                 // Count number of times this packet was acked
	uint8_t dupack_count;
	uint16_t tcp_window;
private:
	long diff;

public:
	ByteRange(seq64_t start, seq64_t end) {
		startSeq = start;
		endSeq = end;
		data_sent_count = 0;
		byte_count = 0;
		data_received_count = 0;
		dupack_count = 0;
		acked = 0;
		ack_count = 0;
		send_tcp_stamp_recv_index = 0;
		updateByteCount();
		original_payload_size = byte_count;
		packet_sent_count = 0;
		packet_received_count = 0;
		packet_retrans_count = 0;
		data_retrans_count = 0;
		rdb_count = 0;
		recv_type = DEF;
		recv_type_num = 1;
		received_tstamp_tcp = 0;
		rdb_miss_count = 0;
		rdb_hit_count = 0;
		diff = 0;
		tcp_window = 0;
		ackTime.tv_sec = 0;
		ackTime.tv_usec = 0;
		fin = 0;
		syn = 0;
		rst = 0;
		original_packet_is_rdb = 0;
		acked_sent = 0;
		app_layer_latency_tstamp = 0;
		sojourn_time = 0;
		sent_data_pkt_pcap_index = -1;
	}

	inline void increase_received(uint32_t tstamp_tcp, timeval tstamp_pcap, bool in_sequence) {

		if (!data_received_count) {
			app_layer_latency_tstamp = in_sequence;
			received_tstamp_tcp = tstamp_tcp;
			received_tstamp_pcap = tstamp_pcap;
		}
		data_received_count++;

		vector< pair<uint32_t, timeval> >::iterator it, it_end;
		it = lost_tstamps_tcp.begin(), it_end = lost_tstamps_tcp.end();
		while (it != it_end) {
			if (it->first == tstamp_tcp) {
				lost_tstamps_tcp.erase(it);
				break;
			}
			it++;
		}
	}

	inline void increase_sent(uint32_t tcp_tsval, uint32_t tcp_tsecr, timeval tstamp_pcap, bool rdb, sent_type sent_t=ST_PKT) {

		if (rdb) {
			rdb_tstamps_tcp.push_back(tcp_tsval);
		}
		else {
			tstamps_tcp.push_back(pair<uint32_t, uint32_t>(tcp_tsval, tcp_tsecr));
		}

		if (sent_t == ST_PKT || sent_t == ST_RST)
			packet_sent_count++;

		if (sent_t == ST_RTR)
			packet_retrans_count++;

		if (sent_t == ST_PURE_ACK)
			acked_sent++;
		else if (sent_t != ST_RST) // RST packets never send data, so only increase the packet sent counter
			data_sent_count++;

		if (sent_t == ST_PKT)
			sent_data_pkt_pcap_index = static_cast<int16_t>(sent_tstamp_pcap.size());

		sent_tstamp_pcap.push_back(pair<timeval, sent_type>(tstamp_pcap, sent_t));
		lost_tstamps_tcp.push_back(pair<uint32_t, timeval>(tcp_tsval, tstamp_pcap));
	}

	void updateByteCount() {
		assert((endSeq - startSeq) < std::numeric_limits<uint16_t>::max());
		byte_count = static_cast<uint16_t>(endSeq - startSeq);
	}

	// Split and make a new range at the end
	ByteRange* splitEnd(seq64_t start, seq64_t end) {
		endSeq = start;
		return split(start, end);
	}

	ByteRange* split(seq64_t start, seq64_t end) {
		ByteRange *new_br = new ByteRange(start, end);
		new_br->packet_sent_count = 0;
		new_br->data_retrans_count = data_retrans_count;
		new_br->data_sent_count = data_sent_count;
		new_br->data_received_count = data_received_count;
		new_br->received_tstamp_tcp = received_tstamp_tcp;
		new_br->tstamps_tcp = tstamps_tcp;
		new_br->rdb_tstamps_tcp = rdb_tstamps_tcp;
		new_br->ackTime = ackTime;
		new_br->acked = acked;
		updateByteCount();
		new_br->sent_tstamp_pcap = sent_tstamp_pcap;
		for (size_t i = 0; i < new_br->sent_tstamp_pcap.size(); i++)
			new_br->sent_tstamp_pcap[i].second = ST_NONE;
		return new_br;
	}

	void registerSACKS(DataSeg* data) { tcp_sacks.push_back(data->tcp_sacks); }
	bool matchReceivedType(RangeManager *rm, bool print=false);
	void printTstampsTcp(ulong limit);

	seq64_t getStartSeq() { return startSeq; }
	seq64_t getEndSeq() { return endSeq; }
	long getSendAckTimeDiff(RangeManager *rm);
	uint8_t getNumRetrans() { return packet_retrans_count; }
	uint8_t getNumBundled() { return rdb_count; }
	uint16_t getNumBytes() { return byte_count; }
	uint16_t getDataSentCount() { return data_sent_count; }
	uint16_t getDataReceivedCount() { return data_received_count; }
	uint16_t getOrinalPayloadSize() { return original_payload_size; }
	int getTotalBytesTransfered() { return byte_count + byte_count * data_retrans_count + byte_count * rdb_count; }
	bool isAcked() { return acked; }
	void insertAckTime(timeval *tv) { ackTime = *tv; acked = 1; }
	void calculateRecvDiff(timeval *recv_tstamp = NULL);
	long getRecvDiff() { return diff; }
	void setRecvDiff(long _diff) { diff = _diff; }
	string strInfo();
	string str();
	void printTstampsPcap();
	timeval* getSendTime();
	timeval* getRecvTime();
	timeval* getAckTime();
	void setRecvTime(timeval *tv) { received_tstamp_pcap = *tv; }
	vector< pair<int, int> > getSojournTimes();
	bool addSegmentEnteredKernelTime(seq64_t seq, timeval &tv);
};

#endif /* BYTERANGE_H */
