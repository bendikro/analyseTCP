#ifndef CONNECTION_H
#define CONNECTION_H

#include "util.h"
#include "RangeManager.h"
#include <cmath>
#include <netinet/in.h>

struct PacketSize {
	timeval time;
	uint16_t packet_size;
	uint16_t payload_size;
	PacketSize(timeval t, uint16_t ps, uint16_t pls) : time(t), packet_size(ps), payload_size(pls) {
	}
};

class PacketSizeGroup {
public:
	vector<PacketSize> packetSizes;
	uint64_t bytes;
	uint64_t _size;
	uint64_t size() {
		return _size;
	}

	void add(PacketSize &ps) {
		packetSizes.push_back(ps);
		bytes += ps.packet_size;
		_size += 1;
	}
	string str() const;
	PacketSizeGroup() : bytes(0), _size(0) {}

	PacketSizeGroup& operator+=(PacketSizeGroup &rhs) {
		bytes += rhs.bytes;
		_size += rhs.size();
		return *this;
	}
};
ofstream& operator<<(ofstream& stream, const PacketSizeGroup& psGroup);

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
	struct in_addr dstIp;
	uint64_t bundleCount; // Number of packets with RDB data
	// Used for calulcating relative sequence number
	uint64_t lastLargestStartSeq;
	uint64_t lastLargestEndSeq;           // This is the last largest sent (relative) end sequence number
	uint32_t lastLargestSeqAbsolute;      // This is the last largest sent (absolute) start sequence number (This value will wrap)
	uint64_t lastLargestRecvEndSeq;       // For reveiver side analyse
	uint32_t lastLargestRecvSeqAbsolute;  // For reveiver side analyse
	uint64_t lastLargestAckSeq;
	uint32_t lastLargestAckSeqAbsolute;
	uint64_t lastLargestSojournEndSeq;       // For reveiver side analyse
	uint32_t lastLargestSojournSeqAbsolute;  // For reveiver side analyse


	void genByteCountGroupedByInterval();

	vector< vector<PacketSize> > packetSizes;
	vector<PacketSizeGroup> packetSizeGroups;

	PacketsStats packetsStats;
	string connKey, senderKey, receiverKey;

	timeval firstSendTime;
	timeval endTime;
	RangeManager *rm;

	Connection(const struct in_addr &src_ip, const uint16_t *src_port,
			   const struct in_addr &dst_ip, const uint16_t *dst_port,
			   uint32_t seq) : nrPacketsSent(0), nrDataPacketsSent(0), totPacketSize(0),
							   totBytesSent(0), totRDBBytesSent(0), totNewDataSent(0),
							   totRetransBytesSent(0), nrRetrans(0), bundleCount(0), lastLargestStartSeq(0),
							   lastLargestEndSeq(0), lastLargestRecvEndSeq(0), lastLargestAckSeq(0),
							   lastLargestSojournEndSeq(0), lastLargestSojournSeqAbsolute(0)
	{
		srcIp                      = src_ip;
		dstIp                      = dst_ip;
		lastLargestSeqAbsolute     = seq;
		lastLargestRecvSeqAbsolute = seq;
		lastLargestAckSeqAbsolute  = seq;
		timerclear(&firstSendTime);
		timerclear(&endTime);
		rm = new RangeManager(this, seq);
		connKey = makeConnKey(src_ip, dst_ip, src_port, dst_port);
		senderKey = makeHostKey(src_ip, src_port);
		receiverKey = makeHostKey(dst_ip, dst_port);
	}

	~Connection() {
		delete rm;
	}

	bool registerSent(struct sendData* pd);
	void registerRange(struct sendData* sd);
	void registerRecvd(struct sendData *sd);
	bool registerAck(struct DataSeg *seg);
	void addConnStats(ConnStats* cs);
	PacketsStats* getBytesLatencyStats();
	void genBytesLatencyStats(PacketsStats* bs);
	void validateRanges();
	timeval get_duration() ;
	void calculateLatencyVariation() { rm->calculateLatencyVariation(); }
	void makeByteLatencyVariationCDF() { rm->makeByteLatencyVariationCDF(); }
	void writeByteLatencyVariationCDF(ofstream *stream);
	void writeSentTimesAndQueueingDelayVariance(const uint64_t first_tstamp, vector<ofstream*> streams) { rm->writeSentTimesAndQueueingDelayVariance(first_tstamp, streams); }
	void genAckLatencyData(long first_tstamp, vector<SPNS::shared_ptr<vector <LatencyItem> > > &diff_times) {
		rm->genAckLatencyData(first_tstamp, diff_times, getConnKey());
	}
	void addRDBStats(int *rdb_sent, int *rdb_miss, int *rdb_hits, int *totBytesSent);
	ulong getNumUniqueBytes();
	string getConnKey() { return connKey; }
	string getSenderKey() { return senderKey; }
	string getReceiverKey() { return receiverKey; }
	void set_analyse_range_interval();
	void calculateRetransAndRDBStats();
	uint32_t getDuration(bool analyse_range_duration);

	void registerPacketSize(const timeval& first_tstamp_in_dump, const timeval& pkt_tstamp, const uint64_t pkt_size, const uint16_t payloadSize);
	void writePacketByteCountAndITT(vector<ofstream*> streams);
};
#endif /* CONNECTION_H */
