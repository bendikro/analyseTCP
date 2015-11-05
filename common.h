#ifndef COMMON_H
#define COMMON_H

/*
  As uint64_t is defined as unsigned long on Linux (gcc/clang) and
  unsigned long long on OSX. Printing such values is troublesome as
  linux requires %lu, and OSX %llu. Therefore we use ullint_t and
  llint_t for variables that must be at least 64 bits, which can be
  printed on all platforms with %llu.

  On Linux (with clang), include the following two defines to test if
  the compiler will give warnings when compiled on OSX where
  (u)int64_t is (unsigned) long long.

#define uint64_t unsigned long long
#define int64_t long long
*/

#define seq32_t uint32_t
// Following types are at least 64 bit
#define seq64_t unsigned long long
#define ullint_t unsigned long long
#define llint_t long long

#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cassert>
#include <ctype.h>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <pcap.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <map>

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef OS_FREEBSD
#include <sys/socket.h>
#endif

#include <netinet/if_ether.h> // Must come after <sys/socket.h> on FreeBSD

#ifdef HAVE_STD_MEMORY_HEADER
  #include <memory>
#elif defined(HAVE_TR1_MEMORY_HEADER)
  #include <tr1/memory>
#else
  #error no C++ memory header defined, perhaps boost?
#endif
#ifdef SHARED_PTR_TR1_NAMESPACE
  #define SPNS std::tr1
#else
  #define SPNS std
#endif

using namespace std;

#include "color_print.h"

#define safe_div(x, y) ((y) != 0 ? ((double) (x)) / (y) : 0.0)

/* Convert a timeval to milliseconds */
#define TV_TO_MS(tv) ((int64_t)((tv).tv_sec * 1000L + ((tv).tv_usec / 1000L)))
#define TV_TO_MICSEC(tv) ((int64_t)((tv).tv_sec * 1000000L + ((tv).tv_usec)))

enum sent_type {ST_NONE, ST_PKT, ST_RTR, ST_PURE_ACK, ST_RST};

/* Compare two timevals */
bool operator==(const timeval& lhs, const timeval& rhs);

/* Class to keep global options */
class GlobOpts {
private:

public:
	static bool aggregate;
	static bool aggOnly;
	static bool aggInfo;
	static bool transport;
	static bool withRecv;
	static bool withLoss;
	static uint64_t lossAggrMs;
	static bool withThroughput;
	static uint64_t throughputAggrMs;
	static bool withCDF;
	static bool relative_seq;
	static bool print_packets;
	static vector <pair<uint64_t, uint64_t> > print_packets_pairs;
	static string sendNatIP;
	static string recvNatIP;
	static in_addr sendNatAddr;
	static in_addr recvNatAddr;
	static bool genAckLatencyFiles;
	static bool genPerPacketStats;
	static bool genPerSegmentStats;
	static string prefix;
	static string RFiles_dir;
	static bool connDetails;
	static bool writeConnDetails;
	static int verbose;
	static bool validate_ranges;
	static int max_retrans_stats;
	static string percentiles;
	static int analyse_start;
	static int analyse_end;
	static long analyse_duration;
	static string sojourn_time_file;
	static bool oneway_delay_variance;
	static bool look_for_get_request;
	/* Debug warning prints */
	static int  debugLevel;
	static bool debugSender;
	static bool debugReceiver;
	static bool print_payload_mismatch_warn;
	static bool print_timestamp_mismatch_warn;
	static bool print_missing_byterange_warn;
	/* Debug test variables */
	static bool conn_key_debug;
};

#define DEBUGL(level) (GlobOpts::debugLevel >= level)
#define DEBUGL_SENDER(level) (GlobOpts::debugSender && GlobOpts::debugLevel >= level)
#define DEBUGL_RECEIVER(level) (GlobOpts::debugReceiver && GlobOpts::debugLevel >= level)


struct DataSeg {
	seq64_t seq;
	seq64_t endSeq;
	seq64_t rdb_end_seq;   /* end seq of rdb data */
	seq32_t seq_absolute;  /* Absolute value of the sequence number */
	seq64_t ack;
	uint16_t window;
	uint16_t payloadSize;       /* Payload size */
	bool retrans : 1,       /* is a retransmission */
		is_rdb : 1,         /* is a rdb packet */
		in_sequence : 1;    // Is the segment expected or out of order
	timeval tstamp_pcap;
	uint32_t tstamp_tcp;
	uint32_t tstamp_tcp_echo;
	u_char flags;
	DataSeg() : seq(0), endSeq(0), rdb_end_seq(0), seq_absolute(0), ack(0),
		window(0), payloadSize(0), retrans(0), is_rdb(0), in_sequence(0),
		tstamp_tcp(0), tstamp_tcp_echo(0), flags(0) {
	}
//	u_char *data;
};

/* Struct used to forward relevant data about an anlysed packet */
struct sendData {
	uint totalSize;     /* Total packet size */
	uint ipSize;        /* IP size */
	uint ipHdrLen;      /* Ip header length */
	uint tcpHdrLen;     /* TCP header length */
	uint tcpOptionLen;  /* TCP header option length */
	DataSeg data;
};


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_HEADER_LINUX_COOKED_MODE 16

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
	in_addr ip_src,ip_dst;  /* source and dest address */
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

/* Linux cooked-mode capture (SLL: sockaddr_ll) */
struct sniff_linux_cooked_mode {
	u_char  packet_type[2];                 /* Type
	                                         * 0: packet was sent to us by somebody else
	                                         * 1: packet was broadcast by somebody else
	                                         * 2: packet was multicast, but not broadcast, by somebody else
	                                         * 3: packet was sent by somebody else to somebody else
	                                         * 4: packet was sent by us
	                                         */
	u_char  link_layer_type[2];              /* Linux ARPHRD_ value for the link layer device type; */
	u_char  link_layer_adress_len[2];        /* length of the link layer address of the sender of the packet (which could be 0) */
	uint64_t link_layer_header_size;         /* number of bytes of the link layer header */
	u_short ether_type;                      /* IP? ARP? RARP? etc */
} __attribute__((packed));


bool endsWith(const string& s, const string& suffix);
string file_and_linenum();
void exit_with_file_and_linenum(int exit_code, string file, int linenum);
void warn_with_file_and_linenum(string file, int linenum);

string seq_pair_str(seq64_t start, seq64_t end);

/* Debug/Verbose printing */

enum debug_type {DSENDER, DRECEIVER};

#define DEBUG_PREFIX_FMT "[DEBUG %d] "
#define PREFIX_LEN 20

void dclprintf(enum debug_type type, int debug_level, int fg_color, const char *format, ...);
void dclfprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, ...);
void dprintf(enum debug_type type, int debug_level, const char *format, ...);
void dfprintf(FILE *stream, enum debug_type type, int debug_level, const char *format, ...);

void vbclprintf(int verbose_level, int fg_color, const char *format, ...);
void vbprintf(int verbose_level, const char *format, ...);
/* END printing */

#endif /* COMMON_H */
