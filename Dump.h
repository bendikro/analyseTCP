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
		//printf("Compare right (%15p) : src ip: %ul, dst ip: %ul, src port: %us, dst port: %us\n", right, right->ip_src.s_addr, right->ip_dst.s_addr, right->src_port, right->dst_port);
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


/* Represents one dump, and keeps globally relevant information */
class Dump {

private:
	string srcIp;
	string dstIp;
	string filename;
	string srcPort;
	string dstPort;
	int sentPacketCount;
	int sentBytesCount;
	int recvPacketCount;
	int recvBytesCount;
	int ackCount;
	uint32_t max_payload_size;
	map<ConnectionMapKey*, Connection*, ConnectionKeyComparator> conns;

	void processSent(const struct pcap_pkthdr* header, const u_char *data);
	void processRecvd(const struct pcap_pkthdr* header, const u_char *data);
	void processAcks(const struct pcap_pkthdr* header, const u_char *data);
	void registerRecvd(const struct pcap_pkthdr* header, const u_char *data);
	void printPacketStats(struct connStats *cs, struct byteStats *bs, bool aggregated);
	void printBytesLatencyStats(struct connStats *cs, struct byteStats* bs, bool aggregated, struct byteStats* aggregatedMin, struct byteStats* aggregatedMax);
public:
	Dump(string src_ip, string dst_ip, string src_port, string dst_port, string fn);
	~Dump();
	uint64_t get_relative_sequence_number(uint32_t ack, uint32_t firstSeq, ulong largestAckSeq, uint32_t largestAckSeqAbsolute);
	void analyseSender();
	void processRecvd(string fn);
	void calculateRetransAndRDBStats();
	void printPacketDetails();
	void printDumpStats();
	void printConns();
	void printStatistics();
	void genRFiles();
	void write_loss_to_file();
	void makeCDF();
	void makeDcCdf();
	void writeCDF();
	void writeDcCdf();
	void writeAggCdf();
	void writeAggDcCdf();
	void free_resources();
	void findTCPTimeStamp(struct DataSeg* data, uint8_t* opts, int option_length);
	Connection* getConn(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort, const uint32_t *seq);
};

#endif /* DUMP_H */
