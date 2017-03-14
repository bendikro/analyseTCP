#ifndef CONNECTION_H
#define CONNECTION_H

#include "util.h"
#include "RangeManager.h"
#include "minicsv.h"

#include <cmath>
#include <netinet/in.h>

seq64_t getRelativeSequenceNumber(seq32_t seq, seq32_t firstSeq, seq64_t largestSeq, seq32_t largestSeqAbsolute, Connection *conn);

/* Represents one connection (srcport/dstport pair) */
class Connection {

public:
	ullint_t nrPacketsSent;
	ullint_t nrDataPacketsSent;
	ullint_t totPacketSize;
	ullint_t totBytesSent;
	ullint_t totRDBBytesSent;
	ullint_t totNewDataSent;
	ullint_t totRetransBytesSent;
	ullint_t nrPacketRetrans; // Not actually used...
	in_addr srcIp;
	in_addr dstIp;
	ullint_t bundleCount; // Number of packets with RDB data
	// Used for calculating relative sequence number
	seq64_t lastLargestStartSeq;
	seq64_t lastLargestEndSeq;           // This is the last largest sent (relative) end sequence number
	seq32_t lastLargestSeqAbsolute;      // This is the last largest sent (absolute) start sequence number (This value will wrap)
	seq64_t lastLargestRecvEndSeq;       // For receiver side analyse
	seq32_t lastLargestRecvSeqAbsolute;  // For receiver side analyse
	seq64_t lastLargestAckSeq;
	seq32_t lastLargestAckSeqAbsolute;
	seq64_t lastLargestSojournEndSeq;       // For receiver side analyse
	seq32_t lastLargestSojournSeqAbsolute;  // For receiver side analyse

	bool closed;
	int ignored_count;                      // Number of packets ignored due to being closed

	vector< vector<PacketSize> > packetSizes;
	vector<PacketSizeGroup> packetSizeGroups;

	PacketsStats packetsStats;
	string connKey, senderKey, receiverKey;

	timeval firstSendTime;
	timeval endTime;
	RangeManager *rm;

	Connection(const in_addr &src_ip, const uint16_t *src_port,
			   const in_addr &dst_ip, const uint16_t *dst_port,
			   seq32_t seq) : nrPacketsSent(0), nrDataPacketsSent(0), totPacketSize(0),
							  totBytesSent(0), totRDBBytesSent(0), totNewDataSent(0),
							  totRetransBytesSent(0), nrPacketRetrans(0), bundleCount(0), lastLargestStartSeq(0),
							  lastLargestEndSeq(0), lastLargestRecvEndSeq(0), lastLargestAckSeq(0),
							  lastLargestSojournEndSeq(0), lastLargestSojournSeqAbsolute(0), closed(false),
							  ignored_count(0)

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

	bool registerSent(PcapPacket *pkt);
	void registerRange(DataSeg *seg);
	void registerRecvd(DataSeg *seg);
	bool registerAck(DataSeg *seg);
	void addConnStats(ConnStats *cs);
	PacketsStats* getBytesLatencyStats();
	void validateRanges();
	timeval get_duration() ;
	void genByteCountGroupedByInterval();
	void calculateLatencyVariation() { rm->calculateLatencyVariation(); }
	void makeByteLatencyVariationCDF() { rm->makeByteLatencyVariationCDF(); }
	void writeByteLatencyVariationCDF(ofstream *stream);
	void writeSentTimesAndQueueingDelayVariance(const int64_t first_tstamp, vector<csv::ofstream*> streams) { rm->writeSentTimesAndQueueingDelayVariance(first_tstamp, streams); }
	void genAckLatencyData(const int64_t first_tstamp, vector<SPNS::shared_ptr<vector <LatencyItem> > > &diff_times) {
		rm->genAckLatencyData(first_tstamp, diff_times, getConnKey());
	}
	void addRDBStats(int *rdb_sent, int *rdb_miss, int *rdb_hits, int *totBytesSent);
	ullint_t getNumUniqueBytes();
	string getConnKey() { return connKey; }
	string getSenderKey() { return senderKey; }
	string getReceiverKey() { return receiverKey; }
	void setAnalyseRangeInterval();
	void calculateRetransAndRDBStats();
	uint32_t getDuration(bool analyse_range_duration);
	void registerPacketSize(const timeval& first_tstamp_in_dump, const timeval& pkt_tstamp, const uint32_t pkt_size,
							const uint16_t payloadSize, bool retrans);
	void writePacketByteCountAndITT(vector<csv::ofstream*> streams);
	seq64_t getRelativeSequenceNumber(seq32_t seq, relative_seq_type type);
};

#endif /* CONNECTION_H */
