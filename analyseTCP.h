/*************************************************************************************
**************************************************************************************
**                                                                                  **
**  analyseRdb - Tool for analysing sender side tcpdump                             **
**               files with regard to latency.                                      **
**                                                                                  **
**  Copyright (C) 2007     Andreas Petlund  - andreas@petlund.no                    **
**                     and Kristian Evensen - kristrev@ifi.uio.no                   **
**                                                                                  **
**     This program is free software; you can redistribute it and/or modify         **
**     it under the terms of the GNU General Public License as published by         **
**     the Free Software Foundation; either version 2 of the License, or            **
**     (at your option) any later version.                                          **
**                                                                                  **
**     This program is distributed in the hope that it will be useful,              **
**     but WITHOUT ANY WARRANTY; without even the implied warranty of               **
**     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                **
**     GNU General Public License for more details.                                 ** 
**                                                                                  **
**     You should have received a copy of the GNU General Public License along      **
**     with this program; if not, write to the Free Software Foundation, Inc.,      **
**     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.                  **
**                                                                                  **
**************************************************************************************
*************************************************************************************/	

#ifndef ANALYSETCP_H
#define ANALYSETCP_H

using namespace std;

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <string>
#include <map>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <limits>
#include <arpa/inet.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <limits.h>
#include <deque>

#define MAX_STAT_RETRANS 15

/* Class to keep global options */
class GlobOpts {
 private:

 public:
  static bool aggregate;
  static bool aggOnly;
  static bool aggInfo;
  static bool transport;
  static int  debugLevel;
  static bool incTrace;
  static bool withRecv;
  static bool withLoss;
  static int lossAggrSeconds;
  static bool withCDF;
  static bool relative_seq;
  static bool print_packets;
  static string sendNatIP;
  static string recvNatIP;
  static bool genRFiles;
  static string prefix;
  static string RFiles_dir;
  static bool rdbDetails;
  static int max_retrans_stats;
};

class GlobStats {
public:
	static map<const long, int> cdf;
	static map<const int, int> dcCdf;
	static float avgDrift;
	static int totNumBytes;
	/* TODO: Create list of retransission statistics based on observed
	   number of retransmissions */
	static vector<string> retrans_filenames;
	// Filled with latency (acked_time - sent_time) data for all the byte ranges
	// Index 0 contains all the data,
	// Index 1 contains latency data for all ranges retransmissted 1 time
	// Index 2 contains latency data for all ranges retransmissted 2 times
	// ...
	static vector<vector <int> *> ack_latency_vectors;

	GlobStats() {
		stringstream filename_tmp;
		retrans_filenames.push_back(string("all-retr-"));
		for (int i = 1; i < GlobOpts::max_retrans_stats +1; i++) {
			filename_tmp.str("");
			filename_tmp << i << "retr-";
			retrans_filenames.push_back(filename_tmp.str());
		}
		for (ulong i = 0; i < retrans_filenames.size(); i++) {
			ack_latency_vectors.push_back(new vector<int>());
		}
	}
	 ~GlobStats() {
		 for (ulong i = 0; i < ack_latency_vectors.size(); i++) {
			 delete ack_latency_vectors[i];
		 }
	 }

	 void prefix_filenames(vector<string> &filenames) {
		 for (ulong i = 0; i < filenames.size(); i++) {
			 filenames[i] = GlobOpts::prefix + filenames[i];
		 }
	 }
};

/* Struct used to pass aggregated data between connections */
struct connStats {
	int duration;
	uint64_t totBytesSent;
	int totRetransBytesSent;
	int totPacketSize;
	int nrDataPacketsSent;
	int nrPacketsSent;
	int nrRetrans;
	int bundleCount;
	int ackCount;
	uint64_t totUniqueBytes;
	uint64_t redundantBytes;
	int rdb_stats_available;
	int rdb_packet_hits;
	int rdb_packet_misses;
	uint64_t rdb_bytes_sent;
	uint64_t rdb_byte_misses;
	uint64_t rdb_byte_hits;
};

struct Percentiles {
	double first_quartile, second_quartile, third_quartile, first_percentile, ninetynine_percentile;
	Percentiles(double first_q, double second_q, double third_q, double first_p, double ninetynine_p) {
		first_quartile = first_q;
		second_quartile = second_q;
		third_quartile = third_q;
		first_percentile = first_p;
		ninetynine_percentile = ninetynine_p;
	}
};

/* Struct used to keep track of bytewise latency stats */
struct byteStats {
	int maxLat;     /* Maximum Latency */
	int minLat;     /* Minimum Latency */
	long long int cumLat;     /* Cumulative latency */
	Percentiles *percentiles_latencies;
	double stdevLat;
	int nrRanges;   /* Number of ranges in conn */
	long long int avgLat;   /* Average latency */
	int retrans[MAX_STAT_RETRANS]; /* Count 1., 2. and 3. retrans */
	map<const int, int> dupacks;
	int maxRetrans; /* MAximum number of retransmissions for a range */
	long long int maxLength;
	long long int minLength;
	long long int cumLength;
	long long int avgLength;
	double stdevLength;
	Percentiles *percentiles_lengths;
};

struct DataSeg {
	ulong seq;
	ulong endSeq;
	ulong ack;
	ulong window;
	uint payloadSize;    /* Payload size */
	bool retrans;        /* is a retransmission */
	bool is_rdb;         /* is a rdb packet */
	ulong rdb_end_seq;   /* end seq of rdb data */
	struct timeval tstamp_pcap;
	uint32_t tstamp_tcp;
	uint32_t tstamp_tcp_echo;
	u_char flags;
	u_char *data;
};

/* Struct used to forward relevant data about an anlysed packet */
struct sendData {
	uint totalSize;     /* Total packet size */
	uint ipSize;        /* IP size */
	uint ipHdrLen;      /* Ip header length */
	uint tcpHdrLen;     /* TCP header length */
	uint tcpOptionLen;  /* TCP header option length */
	uint32_t seq_absolute; /* Absolute value of the sequence number */
	struct DataSeg data;
};


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct ackData {
u_int totalSize;   /* Total packet size */
  u_int ack;
  timeval time;     /* pcap timestamp for packet */
  bool isSyn;
};

bool endsWith(const string& s, const string& suffix);
string file_and_linenum();
void exit_with_file_and_linenum(int exit_code, string file, int linenum);
void warn_with_file_and_linenum(string file, int linenum);
#endif /* ANALYSETCP_H */
