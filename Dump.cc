#include "Dump.h"
#include "color_print.h"
#include "util.h"
#include <memory>
#include <string.h>

#include "Statistics.h"

// griff: temporary, meant to become a CLI option
//        idea of the option is to split a connection into individual HTTP GETs
#define IS_THIS_HTTP_GET 1
#ifdef IS_THIS_HTTP_GET
static void look_for_get_request( const struct pcap_pkthdr* header, const u_char *data );
#endif


/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string src_port, string dst_port, string tcp_port, string fn)
	: filename( fn )
	, srcIp( src_ip )
	, dstIp( dst_ip )
	, srcPort( src_port )
	, dstPort( dst_port )
	, tcpPort( tcp_port )
	, sentPacketCount( 0 )
	, sentBytesCount( 0 )
	, recvPacketCount( 0 )
	, recvBytesCount( 0 )
	, ackCount( 0 )
	, max_payload_size( 0 )
{
	timerclear(&first_sent_time);
	srcIp = src_ip;
	dstIp = dst_ip;
	srcPort = src_port;
	dstPort = dst_port;
    tcpPort = tcp_port;
}

Dump::Dump( const vector<four_tuple_t>& connections, string fn )
	: filename( fn )
	, srcIp( "" )
	, dstIp( "" )
	, srcPort( "" )
	, dstPort( "" )
	, tcpPort( "" )
    , _connections( connections )
	, sentPacketCount( 0 )
	, sentBytesCount( 0 )
	, recvPacketCount( 0 )
	, recvBytesCount( 0 )
	, ackCount( 0 )
	, max_payload_size( 0 )
{
	timerclear(&first_sent_time);
}

Dump::~Dump() {
	free_resources();
}

void Dump::free_resources() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->first;
		delete cIt->second;
	}
	conns.clear();
}


string getConnKey(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort) {
	static char src_ip_buf[INET_ADDRSTRLEN];
	static char dst_ip_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, srcIp, src_ip_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dstIp, dst_ip_buf, INET_ADDRSTRLEN);
	stringstream connKeyTmp;
	connKeyTmp << src_ip_buf << "-" << ntohs(*srcPort) << "-" << dst_ip_buf << "-" << ntohs(*dstPort);
	return connKeyTmp.str();
}

Connection* Dump::getConn(const struct in_addr *srcIp, const struct in_addr *dstIp, const uint16_t *srcPort, const uint16_t *dstPort, const uint32_t *seq)
{
	static struct ConnectionMapKey connKey;
	map<ConnectionMapKey*, Connection*>::iterator it;
	static char src_ip_buf[INET_ADDRSTRLEN];
	static char dst_ip_buf[INET_ADDRSTRLEN];
	memcpy(&connKey.ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKey.ip_dst, dstIp, sizeof(struct in_addr));
	connKey.src_port = *srcPort;
	connKey.dst_port = *dstPort;

	it = conns.find(&connKey);
	// Returning the existing connection key
	if (it != conns.end()) {
		return it->second;
	}

	if (seq == NULL) {
		return NULL;
	}

	inet_ntop(AF_INET, srcIp, src_ip_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dstIp, dst_ip_buf, INET_ADDRSTRLEN);

	Connection *tmpConn = new Connection(*srcIp, ntohs(*srcPort), *dstIp,
										 ntohs(*dstPort), ntohl(*seq));
	ConnectionMapKey *connKeyToInsert = new ConnectionMapKey();
	memcpy(&connKeyToInsert->ip_src, srcIp, sizeof(struct in_addr));
	memcpy(&connKeyToInsert->ip_dst, dstIp, sizeof(struct in_addr));
	connKeyToInsert->src_port = connKey.src_port;
	connKeyToInsert->dst_port = connKey.dst_port;
	conns.insert(pair<ConnectionMapKey*, Connection*>(connKeyToInsert, tmpConn));
	return tmpConn;
}


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender()
{
	int packetCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *data;
	map<ConnectionMapKey*, Connection*>::iterator it, it_end;

	pcap_t *fd = pcap_open_offline(filename.c_str(), errbuf);
	if ( fd == NULL ) {
		cerr << "pcap: Could not open file: " << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	stringstream       filterExp;
	struct bpf_program compFilter;

	bool src_port_range;
	bool dst_port_range;

    if( _connections.size() == 0 )
    {
	    /* Set up pcap filter to include only outgoing tcp
	     * packets with correct ip and port numbers.
	     */
	    src_port_range = !isNumeric(srcPort.c_str(), 10);
	    dst_port_range = !isNumeric(dstPort.c_str(), 10);

	    filterExp << "tcp";
	    if (!srcIp.empty())
		    filterExp << " && src host " << srcIp;
	    if (!srcPort.empty()) {
		    filterExp << " && src " << (src_port_range ? "portrange " : "port ") << srcPort;
	    }
	    if (!dstIp.empty())
		    filterExp << " && dst host " << dstIp;
	    if (!dstPort.empty())
		    filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << dstPort;

        if (!tcpPort.empty())
		    filterExp << " && tcp port " << tcpPort;

	    // Earlier, only packets with TCP payload were used.
	    //filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";
    }
    else
    {
	    src_port_range = false;
	    dst_port_range = false;

        auto it  = _connections.begin();
        auto end = _connections.end();
        for( ; it!=end; it++ )
        {
            filterExp << "( tcp "
                      << "&& src host " << it->ip_left() << " && src port " << it->port_left()
                      << "&& dst host " << it->ip_right() << " && dst port " << it->port_right()
                      << " ) || ( tcp "
                      << "&& src host " << it->ip_right() << " && src port " << it->port_right()
                      << "&& dst host " << it->ip_left() << " && dst port " << it->port_left()
                      << " )";
            if( it+1 != end ) filterExp << " || ";
        }
    }

	if (GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
		cerr << "pcap filter expression: " << (char*)((filterExp.str()).c_str()) << endl;

	/* Filter to get outgoing packets */
	if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	pcap_freecode(&compFilter);

	colored_printf(YELLOW, "Processing sent packets...\n");
	printf("Using filter: '%s'\n", filterExp.str().c_str());

	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd, &header);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd, errMsg);
		} else {
			processSent(&header, data); /* Sniff packet */
			packetCount++;
		}
	} while (data != NULL);

	printf("Finished processing sent packets...\n");

	pcap_close(fd);

	if (GlobOpts::validate_ranges) {
		/* DEBUG: Validate range */
		if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "---------------Begin first validation--------------" << endl;

		it_end = conns.end();
		for (it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
		if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
			cerr << "---------------End of first validation--------------" << endl;
	}

	pcap_t *fd2 = pcap_open_offline(filename.c_str(), errbuf);
	if (fd2 == NULL) {
		cerr << "pcap: Could not open file" << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	filterExp.str("");
	filterExp << "tcp";
	if (!dstIp.empty())
		filterExp << " && src host " << dstIp;
	if (!dstPort.empty())
		filterExp << " && src " << (dst_port_range ? "portrange " : "port ") << dstPort;

	if (!srcIp.empty())
		filterExp << " && dst host " << srcIp;
	if (!srcPort.empty())
		filterExp << " && dst " << (src_port_range ? "portrange " : "port ") << srcPort;

	if (!tcpPort.empty())
		filterExp << " && tcp port " << tcpPort;
/*
  filterExp << " && ((tcp[tcpflags] & tcp-syn) != tcp-syn)"
  << " && ((tcp[tcpflags] & tcp-fin) != tcp-fin)"
  << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";
*/

	filterExp << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
		cerr << "pcap filter expression: " << (char*)((filterExp.str()).c_str()) << endl;

	if (pcap_compile(fd2, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd2, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	pcap_freecode(&compFilter);

	colored_printf(YELLOW, "Processing acknowledgements...\n");

	packetCount = 0;
	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd2, &header);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd2, errMsg);
		} else {
			processAcks(&header, data); /* Sniff packet */
			packetCount++;
		}
	} while (data != NULL);

	pcap_close(fd2);

	printf("Finished processing acknowledgements...\n");

	if (GlobOpts::validate_ranges) {
		/* DEBUG: Validate ranges */
		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "---------------Begin second validation--------------" << endl;
		it_end = conns.end();
		for (it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}

		if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
			cerr << "---------------End of second validation--------------" << endl;
	}
}


void Dump::findTCPTimeStamp(struct DataSeg* data, uint8_t* opts, int option_length) {

	typedef struct {
		uint8_t kind;
		uint8_t size;
	} tcp_option_t;
	int offset = 0;

	while (*opts != 0 && offset < option_length) {
		tcp_option_t* _opt = (tcp_option_t*) (opts + offset);
		if (_opt->kind == 1 /* NOP */) {
			offset += 1;
			continue;
		}
		if (_opt->kind == 8 /* Timestamp */) {
			data->tstamp_tcp = ntohl(*(((uint32_t*) (opts + offset + 2))));
			data->tstamp_tcp_echo = ntohl(*(((uint32_t*) (opts + offset + 6))));
			break;
		}
		if (_opt->size == 0) {
			assert(0 && "opt->size is null!\n");
			break;
		}
		offset += _opt->size;
	}
}

/* Process outgoing packets */
void Dump::processSent(const pcap_pkthdr* header, const u_char *data) {
	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	u_int ipSize;
	u_int ipHdrLen;
	u_int tcpHdrLen;

	/* Finds the different headers+payload */
	//ethernet = (struct sniff_ethernet*) data;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipSize = ntohs(ip->ip_len);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	tcpHdrLen = TH_OFF(tcp) * 4;

	Connection* tmpConn = getConn(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport, &tcp->th_seq);

	/* Prepare packet data struct */
	sendData sd;
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
//	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen); // This gives incorrect result on some packets where the ipSize is wrong (0 in a test trace)
	sd.data.payloadSize  = sd.totalSize - (ipHdrLen + tcpHdrLen + SIZE_ETHERNET);
	sd.data.tstamp_pcap  = header->ts;
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestEndSeq, tmpConn->lastLargestSeqAbsolute, tmpConn);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.retrans      = false;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.flags        = tcp->th_flags;

	if (sd.data.seq == std::numeric_limits<ulong>::max()) {
		if (sd.data.flags & TH_SYN) {
			fprintf(stdout, "Found invalid sequence numbers in beginning of sender dump. Probably old SYN packets\n");
			return;
		}
		printf("Found invalid sequence numbers in beginning of sender dump. Probably the sender dump has retransmissions of packets before the first packet in dump\n");
		return;
	}

	if (first_sent_time.tv_sec == 0 && first_sent_time.tv_usec == 0) {
		first_sent_time = header->ts;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);

#ifdef IS_THIS_HTTP_GET
    look_for_get_request( header, data );
#endif

	sentPacketCount++;
	sentBytesCount += sd.data.payloadSize;

	/*
	printf("Conn: %s : %s (%lu) (%s)\n", tmpConn->getConnKey().c_str(),
		   relative_seq_pair_str(tmpConn->rm, sd.data.seq, sd.data.endSeq).c_str(),
		   (sd.data.endSeq - sd.data.seq), get_TCP_flags_str(sd.data.flags).c_str());
	*/

	if (sd.data.payloadSize > max_payload_size) {
		max_payload_size = sd.data.payloadSize;
	}

	if (tmpConn->registerSent(&sd))
		tmpConn->registerRange(&sd);

	if (GlobOpts::withThroughput) {
		tmpConn->registerPacketSize(first_sent_time, header->ts, header->len, sd.data.payloadSize);
	}
}


/**
 * This function generates the relative sequence number of packets read from pcap files.
 *
 * seq:                The sequence number of the packet
 * firstSeq:           The first sequence number in the stream
 * largestSeq:         The largest relative sequence number that has been read for this stream
 * largestSeqAbsolute: The largest absolute (raw) sequence number that has been read for this stream
 *
 * Returns the relative sequence number or std::numeric_limits<ulong>::max() if it failed.
 **/
uint64_t Dump::get_relative_sequence_number(uint32_t seq, uint32_t firstSeq, ulong largestSeq, uint32_t largestSeqAbsolute, Connection *conn) {
	uint64_t wrap_index;
	uint64_t seq_relative;
	wrap_index = firstSeq + largestSeq;
	wrap_index += 1;

	//printf("get_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u, wrap_index: %lu\n", seq, firstSeq, largestSeq, largestSeqAbsolute, wrap_index);
	// Either seq has wrapped, or a retrans (or maybe reorder if netem is run on sender machine)
	if (seq < largestSeqAbsolute) {
		// This is an earlier sequence number
		if (before(seq, largestSeqAbsolute)) {
			if (before(seq, firstSeq)) {
				return std::numeric_limits<ulong>::max();
				//printf("Before first!\n");
			}
			wrap_index -= (largestSeqAbsolute - seq);
		}
		// Sequence number has wrapped
		else {
			wrap_index += (0 - largestSeqAbsolute) + seq;
		}
	}
	// When seq is greater, it is either newer data, or it is older data because
	// largestSeqAbsolute just wrapped. E.g. largestSeqAbsolute == 10, and seq = 4294967250
	else {
		//printf("wrap_index: %lu\n", wrap_index);
		// This is newer seq
		if (after_or_equal(largestSeqAbsolute, seq)) {
			//printf("after_or_equal\n");
			wrap_index += (seq - largestSeqAbsolute);
			//printf("new wrap_index: %lu\n", wrap_index);
		}
		// Acks older data than largestAckSeqAbsolute, largestAckSeqAbsolute has wrapped.
		else {
			wrap_index -= ((0 - seq) + largestSeqAbsolute);
		}
	}

	wrap_index /= 4294967296L;
	// When seq has wrapped, wrap_index will make sure the relative sequence number continues to grow
	seq_relative = seq + (wrap_index * 4294967296L) - firstSeq;
	if (seq_relative > 9999999999) {// TODO: Do a better check than this, e.g. checking for distance of largestSeq and seq_relative > a large number
		// use stderr for error messages for crying out loud!!!!!
		//fprintf(stderr, "wrap_index: %lu\n", wrap_index);
		//fprintf(stderr, "\nget_relative_sequence_number: seq: %u, firstSeq: %u, largestSeq: %lu, largestSeqAbsolute: %u\n", seq, firstSeq, largestSeq, largestSeqAbsolute);
		//fprintf(stderr, "seq_relative: %lu\n", seq_relative);
		//fprintf(stderr, "Conn: %s\n", conn->getConnKey().c_str());

#if !defined(NDEBUG) && defined(DEBUG)
		fprintf(stderr, "Encountered invalid sequence number for connection %s: %u (firstSeq=%u, largestSeq=%lu, largestSeqAbsolute=%u\n",
				conn->getConnKey().c_str(),
				seq,
				firstSeq,
				largestSeq,
				largestSeqAbsolute);
#endif

		//assert(0 && "Incorrect sequence number calculation!\n");
		return std::numeric_limits<ulong>::max();
	}
	//printf("RETURN seq_relative: %lu\n", seq_relative);
	return seq_relative;
}

/* Process incoming ACKs */
void Dump::processAcks(const struct pcap_pkthdr* header, const u_char *data) {
	static const struct sniff_ip *ip; /* The IP header */
	static const struct sniff_tcp *tcp; /* The TCP header */
	static u_int ipHdrLen;
	static uint32_t ack;
	//static u_long eff_win;        /* window after scaling */
	static bool ret;
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);

	static u_int tcpHdrLen;
	static uint tcpOptionLen;
	tcpHdrLen = TH_OFF(tcp) * 4;
	tcpOptionLen = tcpHdrLen - 20;

	Connection *tmpConn = getConn(&ip->ip_dst, &ip->ip_src, &tcp->th_dport, &tcp->th_sport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		cerr << "Ack for unregistered connection found. Ignoring. Conn: " << getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport) << endl;
		//exit_with_file_and_linenum(1, __FILE__, __LINE__);
		return;
	}
	ack = ntohl(tcp->th_ack);

	DataSeg seg;
	memset(&seg, 0, sizeof(struct DataSeg));
	seg.ack         = get_relative_sequence_number(ack, tmpConn->rm->firstSeq, tmpConn->lastLargestAckSeq, tmpConn->lastLargestAckSeqAbsolute, tmpConn);
	seg.tstamp_pcap = header->ts;
	seg.window = ntohs(tcp->th_win);
	seg.flags  = tcp->th_flags;

	if (seg.ack == std::numeric_limits<ulong>::max()) {
		fprintf(stdout, "Invalid sequence number for ACK! (SYN=%d)\n", !!(seg.flags & TH_SYN));
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&seg, opt, tcpOptionLen);

	ret = tmpConn->registerAck(&seg);
	if (!ret) {
		if (GlobOpts::validate_ranges) {
			printf("DUMP - failed to register ACK!\n");
		}
	}
	else {
		tmpConn->lastLargestAckSeqAbsolute = ack;
		tmpConn->lastLargestAckSeq = seg.ack;
	}
	ackCount++;
}

/* Analyse receiver dump - create CDFs */
void Dump::processRecvd(string recvFn) {
	int packetCount = 0;
	string tmpSrcIp = srcIp;
	string tmpDstIp = dstIp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr h;
	const u_char *data;
	map<uint16_t, Connection*>::iterator it, it_end;

	colored_printf(YELLOW, "Processing receiver dump...\n");

	if (!GlobOpts::sendNatIP.empty()) {
		cerr << "sender side NATing handled" << endl;
		tmpSrcIp = GlobOpts::sendNatIP;
		cerr << "srcIp: " << srcIp << endl;
		cerr << "tmpSrcIp: " << tmpSrcIp << endl;
	}

	if (!GlobOpts::recvNatIP.empty()) {
		cerr << "receiver side NATing handled" << endl;
		tmpDstIp = GlobOpts::recvNatIP;
		cerr << "dstIp: " << dstIp << endl;
		cerr << "tmpDstIp: " << tmpDstIp << endl;
	}

	pcap_t *fd = pcap_open_offline(recvFn.c_str(), errbuf);
	if ( fd == NULL ) {
		cerr << "pcap: Could not open file: " << recvFn << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	/* Set up pcap filter to include only incoming tcp
	   packets with correct IP and port numbers.
	   We exclude packets with no TCP payload. */
	struct bpf_program compFilter;
	stringstream filterExp;

	bool src_port_range = !isNumeric(srcPort.c_str(), 10);
	bool dst_port_range = !isNumeric(dstPort.c_str(), 10);

	filterExp.str("");
	filterExp << "tcp";
	if (!tmpSrcIp.empty())
		filterExp << " && src host " << tmpSrcIp;
	if (!tmpDstIp.empty())
		filterExp << " && dst host " << tmpDstIp;
	if (!srcPort.empty())
		filterExp << " && src " << (src_port_range ? "portrange " : "port ") << srcPort;
	if (!dstPort.empty())
		filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << dstPort;

	//filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";

	/* Filter to get outgoing packets */
	if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		pcap_close(fd);
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	pcap_freecode(&compFilter);

	printf("Using filter: '%s'\n", filterExp.str().c_str());

	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd, &h);
		if (data == NULL) {
			if (packetCount == 0) {
				printf("No packets found!\n");
			}
			//pcap_perror(fd, errMsg);
		} else {
			processRecvd(&h, data); /* Sniff packet */
			packetCount++;
		}
	} while(data != NULL);

	pcap_close(fd);

	printf("Finished processing receiver dump...\n");
}

/* Process packets */
void Dump::processRecvd(const struct pcap_pkthdr* header, const u_char *data) {
	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	static Connection *tmpConn;

    /* Finds the different headers+payload */
//  ethernet = (struct sniff_ethernet*)(data);
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	u_int ipSize = ntohs(ip->ip_len);
	u_int ipHdrLen = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	u_int tcpHdrLen = TH_OFF(tcp)*4;

	tmpConn = getConn(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		static bool warning_printed = false;
		if (warning_printed == false) {
			cerr << "Connection found in recveiver dump that does not exist in sender: " << getConnKey(&ip->ip_src, &ip->ip_dst, &tcp->th_sport, &tcp->th_dport);
			cerr << ". Maybe NAT is in effect?  Exiting." << endl;
			warn_with_file_and_linenum(__FILE__, __LINE__);
			warning_printed = true;
		}
		return;
	}

	if (tmpConn->lastLargestRecvEndSeq == 0 &&
		ntohl(tcp->th_seq) != tmpConn->rm->firstSeq) {
	    if (tcp->th_flags & TH_SYN) {
			printf("Invalid sequence number in SYN packet. This is probably an old connection - discarding...\n");
			return;
		}
	}

	/* Prepare packet data struct */
	struct sendData sd;
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
	sd.data.payloadSize  = ipSize - (ipHdrLen + tcpHdrLen);
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = get_relative_sequence_number(sd.data.seq_absolute, tmpConn->rm->firstSeq, tmpConn->lastLargestRecvEndSeq, tmpConn->lastLargestRecvSeqAbsolute, tmpConn);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.tstamp_pcap  = header->ts;
	sd.data.is_rdb       = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.retrans      = 0;
	sd.data.in_sequence  = 0;
	sd.data.flags        = tcp->th_flags;
	sd.data.window       = ntohs(tcp->th_win);

	if (sd.data.seq == std::numeric_limits<ulong>::max()) {
		if (sd.data.flags & TH_SYN) {
			fprintf(stdout, "Found invalid sequence numbers in beginning of receive dump. Probably an old SYN packet\n");
			return;
		}

		if (tmpConn->lastLargestRecvEndSeq == 0) {
			printf("Found invalid sequence numbers in beginning of receive dump. Probably the sender tcpdump didn't start in time to save this packets\n");
		}
		else {
			printf("Found invalid sequence number in received data!: %u -> %lu\n", sd.data.seq_absolute, (ulong)sd.data.seq);
		}
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	findTCPTimeStamp(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);
	recvPacketCount++;
	recvBytesCount += sd.data.payloadSize;

#ifdef IS_THIS_HTTP_GET
    look_for_get_request( header, data );
#endif

	tmpConn->registerRecvd(&sd);
}

void Dump::calculateRetransAndRDBStats() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->calculateRetransAndRDBStats();
	}
}

void Dump::printPacketDetails() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		cIt->second->rm->printPacketDetails();
	}
}

void Dump::calculateLatencyVariation() {
	map<ConnectionMapKey*, Connection*>::iterator it;
	for (it = conns.begin(); it != conns.end(); ++it) {
		it->second->calculateLatencyVariation();
	}
}

#ifdef IS_THIS_HTTP_GET
static void look_for_get_request( const struct pcap_pkthdr* header, const u_char *data )
{
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	ip = (struct sniff_ip*) (data + SIZE_ETHERNET);
	// u_int ipSize = ntohs(ip->ip_len);
	u_int ipHdrLen = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*) (data + SIZE_ETHERNET + ipHdrLen);
	u_int tcpHdrLen = TH_OFF(tcp)*4;

    u_char* ptr = (u_char *) (data + SIZE_ETHERNET + ipHdrLen + tcpHdrLen);
    if( (ptr - data) < header->caplen )
    {
        u_int payload_len = header->caplen - ( ptr - data );
        if( payload_len > 3 )
        {
            if( not strncmp( (const char*)ptr, "GET", 3 ) )
            {
                cerr << "Found get request in received data" << endl;
                cerr << "payload length=" << header->len - (SIZE_ETHERNET + ipHdrLen + tcpHdrLen) << endl;
                for( u_int i=0; i<payload_len; i++ )
                {
                    cerr << (char)( isprint(ptr[i]) ? ptr[i] : '?' );
                }
                cerr << endl;
            }
        }
    }
}
#endif

