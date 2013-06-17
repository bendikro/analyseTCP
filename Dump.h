#ifndef DUMP_H
#define DUMP_H

#include <string>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <memory>
#include <limits>
#include <arpa/inet.h>

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
  int srcPort;
  int dstPort;
  int sentPacketCount;
  int sentBytesCount;
  int recvPacketCount;
  int recvBytesCount;
  int ackCount;
  map<string, Connection*> conns;

  void processSent(const struct pcap_pkthdr* header, const u_char *data);
  void processRecvd(const struct pcap_pkthdr* header, const u_char *data);
  void processAcks(const struct pcap_pkthdr* header, const u_char *data);
  void registerRecvd(const struct pcap_pkthdr* header, const u_char *data);
  void makeCDF();
  void printCDF();
  void printDcCdf();
  void printAggCdf();
  void printAggDcCdf();
  void printPacketStats(struct connStats *cs, struct byteStats *bs);
  void printBytesLatencyStats(struct byteStats* bs);
  void makeDcCdf();
 public:
  Dump( string src_ip, string dst_ip, int src_port, int dst_port, string fn );
  ulong get_relative_sequence_number(uint32_t ack, uint32_t firstSeq, ulong largestAckSeq, uint32_t largestAckSeqAbsolute);
  ulong get_relative_ack_sequence_number(uint32_t ack, uint32_t firstSeq, ulong largestAckSeq, uint32_t largestAckSeqAbsolute);
  void analyseSender();
  void processRecvd(string fn);
  void printDumpStats();
  void printStatistics();
  void genRFiles();
  void free_resources();
};

#endif /* DUMP_H */
