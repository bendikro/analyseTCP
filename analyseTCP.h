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

/* Local includes */
#include "Dump.h"

/* Class to keep global options */
class GlobOpts{
 private:

 public:
  static bool aggregate;
  static bool aggOnly;
  static bool transport;
  static int  debugLevel;
  static bool incTrace;
  static bool withRecv;
  static string sendNatIP;
  static string recvNatIP;
  static bool genRFiles;
  static string prefix;
};

class GlobStats{
 private:

 public:
  static map<const int, int> cdf;
  static map<const int, int> dcCdf;
  static float avgDrift;
  static int totNumBytes;
  static vector<int> retr1;
  static vector<int> retr2;
  static vector<int> retr3;
  static vector<int> retr4;
  static vector<int> all;
  
};

/* Struct used to pass aggregated data between connections */
struct connStats{
  int totPacketSize;
  int nrPacketsSent;
  int nrRetrans;
  int bundleCount;
  int totUniqueBytes;
};

/* Struct used to keep track of bytewise latency stats */
struct byteStats{
  int maxLat;     /* Maximum Latency */
  int minLat;     /* Minimum Latency */
  int cumLat;     /* Cumulative latency */
  int nrRanges;   /* Number of ranges in conn */
  float avgLat;   /* Average latency */
  int retrans[3]; /* Count 1., 2. and 3. retrans */
  int maxRetrans; /* MAximum number of retransmissions for a range */
};

/* Struct used to forward relevant data about an anlyzed packet */
struct sendData {
  u_int totalSize;   /* Total packet size */
  u_int ipSize;      /* IP size */
  u_int ipHdrLen;    /* Ip header length */
  u_int tcpHdrLen;   /* TCP header length */
  u_int payloadSize; /* Payload size */
  u_long seq;        /* Sequence number */
  u_long endSeq;     /* Seq + payload size */
  timeval time;     /* pcap timestamp for packet */
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

#endif /* ANALYSETCP_H */
