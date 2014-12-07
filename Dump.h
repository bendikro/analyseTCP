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
class Dump {

private:
	timeval first_sent_time;
	string srcIp;
	string dstIp;
	string filename;
	string srcPort;
	string dstPort;
	int64_t sentPacketCount;
	uint64_t sentBytesCount;
	int64_t recvPacketCount;
	uint64_t recvBytesCount;
	uint64_t ackCount;
	uint32_t max_payload_size;
	map<ConnectionMapKey*, Connection*, ConnectionKeyComparator> conns;

	void processSent(const struct pcap_pkthdr* header, const u_char *data);
	void processRecvd(const struct pcap_pkthdr* header, const u_char *data);
	void processAcks(const struct pcap_pkthdr* header, const u_char *data);
	void registerRecvd(const struct pcap_pkthdr* header, const u_char *data);
	void printAggStats(string prefix, string unit, struct connStats *cs, struct BaseStats& bs, struct BaseStats& aggregatedMin, struct BaseStats& aggregatedMax);
	void printStats(string prefix, string unit, struct BaseStats& bs);
	void printPacketStats(struct connStats *cs, struct byteStats *bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax);
	void printBytesLatencyStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax);
	void printPacketITTStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax);
	void writeITT(ofstream& stream, vector<struct SentTime>& sent_times);
public:
	Dump(string src_ip, string dst_ip, string src_port, string dst_port, string fn);
	uint64_t get_relative_sequence_number(uint32_t ack, uint32_t firstSeq, uint64_t largestAckSeq, uint32_t largestAckSeqAbsolute, Connection *conn);
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
	void findTCPTimeStamp(struct DataSeg* data, uint8_t* opts, int option_length);
	Connection* getConn(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort, const uint32_t *seq);
	void fillWithSortedConns(map<ConnectionMapKey*, Connection*, SortedConnectionKeyComparator> &sortedConns);
	void writeSentTimesAndQueueingDelayVariance();
	void writeByteCountGroupedByInterval(); // throughput
};

#endif /* DUMP_H */
