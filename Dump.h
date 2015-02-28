#ifndef DUMP_H
#define DUMP_H

#include <string>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <memory>
#include <limits>
#include <arpa/inet.h>
#include <iomanip>
#include "Connection.h"
#include "fourTuple.h"

/* Forward declarations */
class Connection;

struct ConnectionMapKey {
	struct in_addr ip_src, ip_dst;
	u_short src_port, dst_port;
};

struct ConnectionKeyComparator {
	bool operator()(const ConnectionMapKey*  left, const ConnectionMapKey* right) const {
		//printf("Compare left  (%15p) : src ip: %ul, dst ip: %ul, src port: %us, dst port: %us\n", left, left->ip_src.s_addr, left->ip_dst.s_addr, left->src_port, left->dst_port);
		//printf("Compare right (%15p) : src ip: %ul, dst ip: %ul, src port: %u, dst port: %u\n", right, right->ip_src.s_addr, right->ip_dst.s_addr, right->src_port, right->dst_port);
		bool ret;
		if (left->ip_src.s_addr != right->ip_src.s_addr)
			ret = left->ip_src.s_addr < right->ip_src.s_addr;
		else if (left->src_port != right->src_port)
			ret = left->src_port < right->src_port;
		else if (left->ip_dst.s_addr != right->ip_dst.s_addr)
			ret = left->ip_dst.s_addr < right->ip_dst.s_addr;
		else if (left->dst_port != right->dst_port)
			ret = left->dst_port < right->dst_port;
		else
			ret = false;
		return ret;
	}
};

// Sort by converting ports with ntohs
struct SortedConnectionKeyComparator {
	bool operator()(const ConnectionMapKey*  left, const ConnectionMapKey* right) const {
		//printf("Compare left  (%15p) : src ip: %ul, dst ip: %ul, src port: %us, dst port: %us\n", left, left->ip_src.s_addr, left->ip_dst.s_addr, left->src_port, left->dst_port);
		//printf("Compare right (%15p) : src ip: %ul, dst ip: %ul, src port: %u, dst port: %u\n", right, right->ip_src.s_addr, right->ip_dst.s_addr, right->src_port, right->dst_port);
		bool ret;
		if (left->ip_src.s_addr != right->ip_src.s_addr)
			ret = left->ip_src.s_addr < right->ip_src.s_addr;
		else if (ntohs(left->src_port) != ntohs(right->src_port))
			ret = ntohs(left->src_port) < ntohs(right->src_port);
		else if (left->ip_dst.s_addr != right->ip_dst.s_addr)
			ret = left->ip_dst.s_addr < right->ip_dst.s_addr;
		else if (ntohs(left->dst_port) != ntohs(right->dst_port))
			ret = ntohs(left->dst_port) < ntohs(right->dst_port);
		else
			ret = false;
		return ret;
	}
};


/* Represents one dump, and keeps globally relevant information */
class Dump
{
private:
	timeval first_sent_time;
	string filename;

	string srcIp;
	string dstIp;
	string srcPort; /* specify tcp.src in filter */
	string dstPort; /* specify tcp.dst in filter */
    string tcpPort; /* specify tcp.port in filter */
    vector<four_tuple_t> _connections;

	int64_t sentPacketCount;
	uint64_t sentBytesCount;
	int64_t recvPacketCount;
	uint64_t recvBytesCount;
	uint64_t ackCount;
	uint32_t max_payload_size;
	map<ConnectionMapKey*, Connection*, ConnectionKeyComparator> conns;

	void processSent(const pcap_pkthdr* header, const u_char *data);
	void processRecvd(const pcap_pkthdr* header, const u_char *data);
	void processAcks(const pcap_pkthdr* header, const u_char *data);
	void registerRecvd(const pcap_pkthdr* header, const u_char *data);
	void printAggStats(string prefix, string unit, connStats *cs, BaseStats& bs, BaseStats& aggregatedMin, BaseStats& aggregatedMax);
	void printStats(string prefix, string unit, BaseStats& bs);
	void writeITT(ofstream& stream, vector<SentTime>& sent_times);
	void printStatsAggr(string prefix, string unit, connStats *cs, BaseStats& bs, BaseStats& aggregatedMin,
						BaseStats& aggregatedAvg, BaseStats& aggregatedMax);
	void printBytesLatencyStatsAggr(connStats *cs, AggrPacketStats &aggrStats);
	void printBytesLatencyStatsConn(PacketStats* bs);
	void printBytesLatencyStats(PacketStats* bs);
	void printPayloadStats(PacketStats *ps);
	void printPayloadStatsAggr(connStats *cs, AggrPacketStats &aggrStats);
	void printPacketStats(connStats *cs);
	void printPacketITTStats(PacketStats* bs);
	void printPacketITTStatsAggr(connStats *cs, AggrPacketStats &aggrStats);

public:
    /** Version used by analyseTCP
     *  It may represent an entire trace, or one that is retricted to a set of given src and dest
     *  IP addresses and ports.
     */
	Dump(string src_ip, string dst_ip, string src_port, string dst_port, string tcp_port, string fn);

    /** Version used by analyseDASH
     *  It represents a subset of a trace that contains an arbitrary number of connection
     *  that must be specified completely by a 4-tuple.
     */
	Dump( const vector<four_tuple_t>& connections, string fn );

	uint64_t get_relative_sequence_number(uint32_t ack, uint32_t firstSeq, ulong largestAckSeq, uint32_t largestAckSeqAbsolute, Connection *conn);
	void analyseSender();
	void processRecvd(string fn);
	void calculateRetransAndRDBStats();
	void printPacketDetails();
	void printDumpStats();
	void printConns();
	void printStatistics();
	void genAckLatencyFiles();
	void writePacketByteCountAndITT();
	void write_loss_to_file();
	void calculateLatencyVariation();
	void makeByteLatencyVariationCDF();
	void writeByteLatencyVariationCDF();
	void writeAggByteLatencyVariationCDF();
	void free_resources();
	void findTCPTimeStamp(DataSeg* data, uint8_t* opts, int option_length);
	Connection* getConn(const in_addr *srcIp, const in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort, const uint32_t *seq);
	void fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns);
	void writeSentTimesAndQueueingDelayVariance();
	void writeByteCountGroupedByInterval(); // throughput
};

#endif /* DUMP_H */
