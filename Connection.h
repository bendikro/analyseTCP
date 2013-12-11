#ifndef CONNECTION_H
#define CONNECTION_H

/* Forward declarations */
class RangeManager;

#include "RangeManager.h"
#include <math.h>
#include <netinet/in.h>

/* Represents one connection (srcport/dstport pair) */
class Connection {

public:
	int nrPacketsSent;
	int nrDataPacketsSent;
	int totPacketSize;
	long long totBytesSent;
	int totRDBBytesSent;
	int totNewDataSent;
	int totRetransBytesSent;
	int nrRetrans;
	struct in_addr srcIp;
	uint16_t srcPort;
	struct in_addr dstIp;
	uint16_t dstPort;
	int bundleCount; // Number of packets with RDB data
	// Used for calulcating relative sequence number
	uint64_t lastLargestStartSeq;
	uint64_t lastLargestEndSeq;           // This is the last largest sent (relative) end sequence number
	uint32_t lastLargestSeqAbsolute;      // This is the last largest sent (absolute) start sequence number (This value will wrap)
	uint64_t lastLargestRecvEndSeq;       // For reveiver side analyse
	uint32_t lastLargestRecvSeqAbsolute;  // For reveiver side analyse
	uint64_t lastLargestAckSeq;
	uint32_t lastLargestAckSeqAbsolute;

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
	void makeCDF();
	void writeCDF(ofstream *stream);
	void writeDcCdf(ofstream *stream);
	void makeDcCdf();
	void addRDBStats(int *rdb_sent, int *rdb_miss, int *rdb_hits, int *totBytesSent);
	void genRFiles();
	ulong getNumUniqueBytes();
	string getConnKey();
	string getSrcIp();
	string getDstIp();
	void set_analyse_range_interval();
	void calculateRetransAndRDBStats();
	uint32_t getDuration(bool analyse_range_duration);
};
#endif /* CONNECTION_H */
