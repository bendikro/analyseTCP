#ifndef CONNECTION_H
#define CONNECTION_H

#include "RangeManager.h"
#include <math.h>
#include <netinet/in.h>

struct PacketSize {
	timeval time;
	uint16_t packet_size;
	uint16_t payload_size;
	PacketSize(timeval t, uint16_t ps, uint16_t pls) : time(t), packet_size(ps), payload_size(pls) {
	}
};

/* Represents one connection (srcport/dstport pair) */
class Connection {

public:
	uint64_t nrPacketsSent;
	uint64_t nrDataPacketsSent;
	uint64_t totPacketSize;
	uint64_t totBytesSent;
	uint64_t totRDBBytesSent;
	uint64_t totNewDataSent;
	uint64_t totRetransBytesSent;
	uint64_t nrRetrans;
	struct in_addr srcIp;
	uint16_t srcPort;
	struct in_addr dstIp;
	uint16_t dstPort;
	uint64_t bundleCount; // Number of packets with RDB data
	// Used for calulcating relative sequence number
	uint64_t lastLargestStartSeq;
	uint64_t lastLargestEndSeq;           // This is the last largest sent (relative) end sequence number
	uint32_t lastLargestSeqAbsolute;      // This is the last largest sent (absolute) start sequence number (This value will wrap)
	uint64_t lastLargestRecvEndSeq;       // For reveiver side analyse
	uint32_t lastLargestRecvSeqAbsolute;  // For reveiver side analyse
	uint64_t lastLargestAckSeq;
	uint32_t lastLargestAckSeqAbsolute;

	vector< vector<struct PacketSize> > packetSizes;

	timeval firstSendTime;
	timeval endTime;
	RangeManager *rm;

	Connection(struct in_addr src_ip, uint16_t src_port,
						   struct in_addr dst_ip, uint16_t dst_port,
						   uint32_t seq) : nrPacketsSent(0), nrDataPacketsSent(0), totPacketSize(0),
										   totBytesSent(0), totRDBBytesSent(0), totNewDataSent(0),
										   totRetransBytesSent(0), nrRetrans(0), bundleCount(0), lastLargestStartSeq(0),
										   lastLargestEndSeq(0), lastLargestRecvEndSeq(0), lastLargestAckSeq(0)
	{
		srcIp                      = src_ip;
		srcPort                    = src_port;
		dstIp                      = dst_ip;
		dstPort                    = dst_port;
		lastLargestSeqAbsolute     = seq;
		lastLargestRecvSeqAbsolute = seq;
		lastLargestAckSeqAbsolute  = seq;
		timerclear(&firstSendTime);
		timerclear(&endTime);
		rm = new RangeManager(this, seq);
	}

	~Connection() {
		delete rm;
	}

	bool registerSent(struct sendData* pd);
	void registerRange(struct sendData* sd);
	void registerRecvd(struct sendData *sd);
	bool registerAck(struct DataSeg *seg);
	void addPacketStats(struct connStats* cs);
	void genBytesLatencyStats(struct byteStats* bs);
	void validateRanges();
	timeval get_duration() ;
	void calculateLatencyVariation() { rm->calculateLatencyVariation(); }
	void makeByteLatencyVariationCDF() { rm->makeByteLatencyVariationCDF(); }
	void writeByteLatencyVariationCDF(ofstream *stream);
	void writeSentTimesAndQueueingDelayVariance(const uint64_t first, ofstream& stream) { rm->writeSentTimesAndQueueingDelayVariance(first, stream); }
	void addRDBStats(int *rdb_sent, int *rdb_miss, int *rdb_hits, int *totBytesSent);
	void genAckLatencyFiles(long first_tstamp) { rm->genAckLatencyFiles(first_tstamp, getConnKey()); }
	ulong getNumUniqueBytes();
	string getConnKey();
	string getSrcIp();
	string getDstIp();
	void set_analyse_range_interval();
	void calculateRetransAndRDBStats();
	uint32_t getDuration(bool analyse_range_duration);

	void registerPacketSize(const timeval& first_tstamp_in_dump, const timeval& pkt_tstamp, const uint64_t pkt_size, const uint16_t payloadSize);
	void writePacketByteCountAndITT(ofstream* all_stream, ofstream* conn_stream);
};
#endif /* CONNECTION_H */
