#ifndef PACKET_PARSE_UTILS_H
#define PACKET_PARSE_UTILS_H

#include "common.h"

/* Forward declarations */
class Connection;

#define seq32_t uint32_t  // Used for absolute sequence numbers (the values in the TCP headers)
#define seq64_t ullint_t  // Used for relative sequence numbers, which starts on 0 for the first packet

typedef pair<seq64_t, seq64_t> sack_t;
typedef vector< sack_t > sack_list_t;
typedef shared_ptr< sack_list_t > sack_list_ptr_t;


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


enum sack_kind : uint8_t {
	tcp_opt_end = 0, /* End of options list */
	tcp_opt_nop = 1, /* NOP */
	tcp_opt_sack = 5,
	tcp_opt_timestamp = 8,
};

typedef struct {
	sack_kind kind;
	uint8_t size;
} tcp_option_t;


class DataSeg {
public:
	seq64_t seq;
	seq64_t endSeq;
	seq64_t rdb_end_seq;   /* end seq of rdb data */
	seq64_t ack;
	seq32_t seq_absolute;  /* Absolute value of the sequence number */
	uint16_t window;
	uint16_t payloadSize;  /* Payload size */
	bool retrans : 1,      /* Is a retransmission */
	     is_rdb : 1,       /* Is a rdb packet */
	     sacks : 1,        /* Has SACK blocks */
	     in_sequence : 1;  /* Is the segment expected or out of order */
	u_char flags;
	timeval tstamp_pcap;
	uint32_t tstamp_tcp;
	uint32_t tstamp_tcp_echo;
	shared_ptr <sack_list_t> tcp_sacks;

	DataSeg() {
		tcp_sacks = shared_ptr <sack_list_t> (new sack_list_t);
		reset();
	}

	void reset() {
		tcp_sacks->clear();
		retrans = is_rdb = sacks = in_sequence = 0;
		flags = 0;
		window = payloadSize = 0;
		seq_absolute = tstamp_tcp = tstamp_tcp_echo = 0;
		seq = endSeq = rdb_end_seq = ack = 0;
	}

	void addTcpSack(sack_t tcp_sack) {
		tcp_sacks->push_back(tcp_sack);
	}
};

/* Struct used to forward relevant data about an analysed packet */
struct PcapPacket {
	uint caplen;
	uint totalSize;        /* Total packet size including headers */
	uint ipSize;           /* IP size */
	uint ipHdrLen;         /* Ip header length */
	uint tcpHdrLen;        /* TCP header length */
	uint tcpOptionLen;     /* TCP header option length */
	uint tcpPayloadOffset; /* Offset into the packet where TCP payload begins */
	DataSeg seg;           /* The parsed data segment */
};


class PcapParse {
public:
	pcap_t *fd;
	pcap_pkthdr header;
	u_char *data;
	u_int link_layer_header_size; /* Size of link layer header */
	sniff_ethernet *ethernet;     /* The ethernet header */
	sniff_ip *ip;                 /* The IP header */
	sniff_tcp *tcp;               /* The TCP header */
	PcapPacket pkt;

	void handlePacketParseWarnings(Connection *conn, enum debug_type type);
	void setPcapFilter(stringstream &filterExp);
	void parsePacket();
	void openPcap(string &filename);
	bool parseTCPOptions(Connection *conn, relative_seq_type seq_type);
};


class TCPOptParser {
public:
	uint8_t* opts;
	PcapParse *parsePkt;
	ulong tcp_opts_end_byte; // The number of tcp options bytes available in the captured data

	TCPOptParser(PcapParse *_parsePkt) : parsePkt(_parsePkt) {
		opts = ((uint8_t*) parsePkt->tcp) + 20;
		tcp_opts_end_byte = min(parsePkt->pkt.caplen, parsePkt->pkt.tcpPayloadOffset) -
			(parsePkt->link_layer_header_size + parsePkt->pkt.ipHdrLen + 20);
	}

	uint8_t* getTcpOptValuePtr(ulong offset, size_t value_size, sack_kind kind) {
		if (((offset) + value_size) > tcp_opts_end_byte) {

			if (GlobOpts::verbose > 0 && GlobOpts::print_pkt_header_caplen_truncated_warn) {
				vbclfprintf(stderr, 1, COLOR_WARN, "Attempted to access TCP %s option %lu bytes outside of the captured data!\n",
							kind == tcp_opt_timestamp ? "Timestamp" : "SACK",
							(((ulong) offset) + value_size) - tcp_opts_end_byte);
			}
			return NULL;
		}
		return opts + offset;
	}
};


std::string get_TCP_flags_str(u_char flags);

string seq_pair_str(seq64_t start, seq64_t end);

/*
  Used to test if a sequence number comes after another
  These handle when the newest sequence number has wrapped
*/
inline bool before(seq32_t seq1, seq32_t seq2) {
	return (signed int) (seq1 - seq2) < 0;
}

#define after(seq2, seq1)   before(seq1, seq2)

inline bool after_or_equal(seq32_t seq1, seq32_t seq2) {
	return (signed int) (seq2 - seq1) >= 0;
}


#endif /* PACKET_PARSE_UTILS_H */
