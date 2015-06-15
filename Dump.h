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

#include <stdexcept>      // std::invalid_argument

/* Forward declarations */
class Connection;
class Statistics;

struct ConnectionMapKey {
	in_addr ip_src, ip_dst;
	u_short src_port, dst_port;
};

extern bool conn_key_debug;

struct ConnectionKeyComparator {
	bool operator()(const ConnectionMapKey*  left, const ConnectionMapKey* right) const {
		//if (conn_key_debug) {
		//	printf("Compare left  (%15p) : src ip: %ul, dst ip: %ul, src port: %u, dst port: %u\n", left, left->ip_src.s_addr, left->ip_dst.s_addr, left->src_port, left->dst_port);
		//	printf("Compare right (%15p) : src ip: %ul, dst ip: %ul, src port: %u, dst port: %u\n", right, right->ip_src.s_addr, right->ip_dst.s_addr, right->src_port, right->dst_port);
		//}
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

	string filterSrcIp;
	string filterDstIp;
	string filterSrcPort; /* specify tcp.src in filter */
	string filterDstPort; /* specify tcp.dst in filter */
	string filterTCPPort; /* specify tcp.port in filter */
	vector<four_tuple_t> _connections;

	llint_t sentPacketCount;
	llint_t recvPacketCount;
	ullint_t sentBytesCount;
	ullint_t recvBytesCount;
	ullint_t ackCount;
	uint32_t max_payload_size;
	map<ConnectionMapKey*, Connection*, ConnectionKeyComparator> conns;

	void processSent(const pcap_pkthdr* header, const u_char *data);
	void processRecvd(const pcap_pkthdr* header, const u_char *data);
	void processAcks(const pcap_pkthdr* header, const u_char *data);
	void registerRecvd(const pcap_pkthdr* header, const u_char *data);

public:
	/** Version used by analyseTCP
	 *	It may represent an entire trace, or one that is retricted to a set of given src and dest
	 *	IP addresses and ports.
	 */
	Dump(string src_ip, string dst_ip, string src_port, string dst_port, string tcp_port, string fn);

	/** Version used by analyseDASH
	 *	It represents a subset of a trace that contains an arbitrary number of connection
	 *	that must be specified completely by a 4-tuple.
	 */
	Dump( const vector<four_tuple_t>& connections, string fn );

	~Dump();

	seq64_t getRelativeSequenceNumber(seq32_t ack, seq32_t firstSeq, seq64_t largestAckSeq, seq32_t largestAckSeqAbsolute, Connection *conn);
	void analyseSender();
	void processRecvd(string fn);
	void calculateRetransAndRDBStats();
	void printPacketDetails();
	void findTCPTimeStamp(DataSeg* data, uint8_t* opts, uint option_length);
	Connection* getConn(const in_addr &srcIpAddr, const in_addr &dstIpAddr, const uint16_t *srcPort, const uint16_t *dstPort, const seq32_t *seq);
	Connection* getConn(string &srcIpStr, string &dstIpStr, string &srcPortStr, string &dstPortStr);
	void calculateLatencyVariation();
	void calculateSojournTime();
	friend class Statistics;
};

#endif /* DUMP_H */
