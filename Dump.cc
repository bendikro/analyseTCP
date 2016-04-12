#include <memory>
#include <string.h>

#include "Dump.h"
#include "color_print.h"
#include "util.h"
#include "Statistics.h"

static void look_for_get_request(const pcap_pkthdr* header, const u_char *data, u_int link_layer_header_size);

/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string tcp_ip, string src_port, string dst_port, string tcp_port, string fn)
	: filename(fn)
	, filterSrcIp(src_ip)
	, filterDstIp(dst_ip)
	, filterTCPIp(tcp_ip)
	, filterSrcPort(src_port)
	, filterDstPort(dst_port)
	, filterTCPPort(tcp_port)
	, sentPacketCount(0)
	, recvPacketCount(0)
	, sentBytesCount(0)
	, recvBytesCount(0)
	, ackCount(0)
	, max_payload_size(0)
{
	timerclear(&first_sent_time);
}

Dump::Dump(const vector<four_tuple_t>& connections, string fn)
	: filename(fn)
	, filterSrcIp("")
	, filterDstIp("")
	, filterTCPIp("")
	, filterSrcPort("")
	, filterDstPort("")
	, filterTCPPort("")
	, _connections(connections)
	, sentPacketCount(0)
	, recvPacketCount(0)
	, sentBytesCount(0)
	, recvBytesCount(0)
	, ackCount(0)
	, max_payload_size(0)
{
	timerclear(&first_sent_time);
}

Dump::~Dump() {
	map<ConnectionMapKey*, Connection*>::iterator cIt, cItEnd;
	for (cIt = conns.begin(); cIt != conns.end(); cIt++) {
		delete cIt->first;
		delete cIt->second;
	}
	conns.clear();
}

Connection* Dump::getConn(const in_addr &srcIpAddr, const in_addr &dstIpAddr, const uint16_t *srcPort, const uint16_t *dstPort, const seq32_t *seq)
{
	ConnectionMapKey connKey;
	map<ConnectionMapKey*, Connection*>::iterator it;
	memcpy(&connKey.ip_src, &srcIpAddr, sizeof(in_addr));
	memcpy(&connKey.ip_dst, &dstIpAddr, sizeof(in_addr));
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

	Connection *tmpConn = new Connection(srcIpAddr, srcPort, dstIpAddr, dstPort, ntohl(*seq));
	ConnectionMapKey *connKeyToInsert = new ConnectionMapKey();
	memcpy(&connKeyToInsert->ip_src, &srcIpAddr, sizeof(in_addr));
	memcpy(&connKeyToInsert->ip_dst, &dstIpAddr, sizeof(in_addr));
	connKeyToInsert->src_port = connKey.src_port;
	connKeyToInsert->dst_port = connKey.dst_port;
	conns.insert(pair<ConnectionMapKey*, Connection*>(connKeyToInsert, tmpConn));
	vbprintf(2, "New connection: %s\n", tmpConn->getConnKey().c_str());
	return tmpConn;
}

Connection* Dump::getConn(string &srcIpStr, string &dstIpStr, string &srcPortStr, string &dstPortStr)
{
	in_addr srcIpAddr;
	in_addr dstIpAddr;

	uint16_t srcPort = htons(static_cast<uint16_t>(std::stoul(srcPortStr)));
	uint16_t dstPort = htons(static_cast<uint16_t>(std::stoul(dstPortStr)));

	if (!inet_pton(AF_INET, srcIpStr.c_str(), &srcIpAddr)) {
		colored_fprintf(stderr, RED, "Failed to convert source IP '%s'\n", srcIpStr.c_str());
	}

	if (!inet_pton(AF_INET, dstIpStr.c_str(), &dstIpAddr)) {
		colored_fprintf(stderr, RED, "Failed to convert destination IP '%s'\n", srcIpStr.c_str());
	}
	return getConn(srcIpAddr, dstIpAddr, &srcPort, &dstPort, NULL);
}

/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender()
{
	int packetCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_pkthdr header;
	const u_char *data;

	pcap_t *fd = pcap_open_offline(filename.c_str(), errbuf);
	if (fd == NULL) {
		cerr << "pcap: Could not open file: " << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	int type = pcap_datalink(fd);
	u_int link_layer_header_size;

	switch (type) {
	case DLT_EN10MB: {
		link_layer_header_size = SIZE_ETHERNET;
		break;
	}
	case DLT_LINUX_SLL: {
		link_layer_header_size = SIZE_HEADER_LINUX_COOKED_MODE;
		break;
	}
	default: {
		fprintf(stderr, "Unsupported link layer type: %d ('%s')\n", type, pcap_datalink_val_to_name(type));
		exit(1);
	}
	}

	stringstream filterExp;
	bpf_program compFilter;

	bool src_port_range;
	bool dst_port_range;

    if (_connections.size() == 0) {
	    /* Set up pcap filter to include only outgoing tcp
	     * packets with correct ip and port numbers.
	     */
	    src_port_range = !isNumeric(filterSrcPort.c_str(), 10);
	    dst_port_range = !isNumeric(filterDstPort.c_str(), 10);

	    filterExp << "tcp";
	    if (!filterSrcIp.empty())
		    filterExp << " && src host " << filterSrcIp;
	    if (!filterSrcPort.empty()) {
		    filterExp << " && src " << (src_port_range ? "portrange " : "port ") << filterSrcPort;
	    }
	    if (!filterDstIp.empty())
		    filterExp << " && dst host " << filterDstIp;
	    if (!filterDstPort.empty())
		    filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << filterDstPort;

        if (!filterTCPPort.empty())
		    filterExp << " && tcp port " << filterTCPPort;

		if (!filterTCPIp.empty())
		    filterExp << " && host " << filterTCPIp;

	    // Earlier, only packets with TCP payload were used.
	    //filterExp << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";
    } else {
	    src_port_range = false;
	    dst_port_range = false;

        auto it  = _connections.begin();
        auto end = _connections.end();
        for (; it!=end; it++)
        {
            filterExp << "( tcp "
                      << "&& src host " << it->ip_left() << " && src port " << it->port_left()
                      << "&& dst host " << it->ip_right() << " && dst port " << it->port_right()
                      << " ) || ( tcp "
                      << "&& src host " << it->ip_right() << " && src port " << it->port_right()
                      << "&& dst host " << it->ip_left() << " && dst port " << it->port_left()
                      << " )";
            if (it+1 != end) filterExp << " || ";
        }
    }

	vbprintf(1, "using pcap filter expression: '%s'\n", (char*) filterExp.str().c_str());

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

	if (DEBUGL_SENDER(1)) {
		colored_printf(YELLOW, "Processing sent packets...\n");
		printf("Using filter: '%s'\n", filterExp.str().c_str());
	}

	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd, &header);
		if (data == NULL) {
			//char errMsg[50];
			//sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd, errMsg);
		} else {
			processSent(&header, data, link_layer_header_size); /* Sniff packet */
			packetCount++;
		}
	} while (data != NULL);

	vbclprintf(1, YELLOW, "Finished processing sent packets...\n");

	pcap_close(fd);

	if (GlobOpts::validate_ranges) {
		/* DEBUG: Validate range */
		auto it_end = conns.end();
		for (auto it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
	}

	vbclprintf(1, YELLOW, "Processing acknowledgements...\n");

	pcap_t *fd2 = pcap_open_offline(filename.c_str(), errbuf);
	if (fd2 == NULL) {
		cerr << "pcap: Could not open file" << filename << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	filterExp.str("");
	filterExp << "tcp";
	if (!filterDstIp.empty())
		filterExp << " && src host " << filterDstIp;
	if (!filterDstPort.empty())
		filterExp << " && src " << (dst_port_range ? "portrange " : "port ") << filterDstPort;

	if (!filterSrcIp.empty())
		filterExp << " && dst host " << filterSrcIp;
	if (!filterSrcPort.empty())
		filterExp << " && dst " << (src_port_range ? "portrange " : "port ") << filterSrcPort;

	if (!filterTCPPort.empty())
		filterExp << " && tcp port " << filterTCPPort;

	filterExp << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";

	vbprintf(1, "Using pcap filter expression: '%s'\n", (char*) filterExp.str().c_str());

	if (pcap_compile(fd2, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	if (pcap_setfilter(fd2, &compFilter) == -1) {
		fprintf(stderr, "Couldn't install filter '%s'. Error: %s\n", filterExp.str().c_str(), pcap_geterr(fd));
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}
	pcap_freecode(&compFilter);

	packetCount = 0;
	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd2, &header);
		if (data == NULL) {
			char errMsg[50];
			sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd2, errMsg);
		} else {
			processAcks(&header, data, link_layer_header_size); /* Sniff packet */
			packetCount++;
		}
	} while (data != NULL);

	pcap_close(fd2);

	if (DEBUGL_SENDER(1)) {
		printf("Finished processing acknowledgements...\n");
	}

	if (GlobOpts::validate_ranges) {
		auto it_end = conns.end();
		for (auto it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
	}
}


void Dump::parseTCPOptions(DataSeg* data, uint8_t* opts, uint option_length,
						   Connection* tmpConn = NULL,
						   relative_seq_type seq_type = RELSEQ_NONE) {

	typedef struct {
		uint8_t kind;
		uint8_t size;
	} tcp_option_t;
	uint offset = 0;

	while (*opts != 0 && offset < option_length) {
		tcp_option_t* _opt = (tcp_option_t*) (opts + offset);
		if (_opt->kind == 0) { /* End of options list */
			break;
		}
		if (_opt->kind == 1) {  /* NOP */
			offset += 1;
			continue;
		}
		if (_opt->kind == 8) {  /* Timestamp */
			data->tstamp_tcp = ntohl(*(((uint32_t*) (opts + offset + 2))));
			data->tstamp_tcp_echo = ntohl(*(((uint32_t*) (opts + offset + 6))));
		}
		if (_opt->kind == 5 && seq_type != RELSEQ_NONE) {  /* SACK */
			int blocks = (_opt->size - 2) / 8;
			data->sacks = true;
			for (int i = 0; i < blocks; i++) {
				seq64_t left = ntohl(*(((uint32_t*) (opts + offset + 2 + (4 * blocks * i)))));
				seq64_t right = ntohl(*(((uint32_t*) (opts + offset + 6  + (4 * blocks * i)))));
				left = tmpConn->getRelativeSequenceNumber(left, RELSEQ_SEND_ACK);
				right = tmpConn->getRelativeSequenceNumber(right, RELSEQ_SEND_ACK);
				data->tcp_sacks.push_back(pair<uint64_t, uint32_t>(left, right));
			}
		}
		offset += _opt->size;
	}
}

/* Process outgoing packets */
void Dump::processSent(const pcap_pkthdr* header, const u_char *data, u_int link_layer_header_size) {
	//const sniff_ethernet *ethernet; /* The ethernet header */
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	u_int ipSize;
	u_int ipHdrLen;
	u_int tcpHdrLen;

	/* Finds the different headers+payload */
	//ethernet = (sniff_ethernet*) data;
	ip = (sniff_ip*) (data + link_layer_header_size);
	ipSize = ntohs(ip->ip_len);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (sniff_tcp*) (data + link_layer_header_size + ipHdrLen);
	tcpHdrLen = TH_OFF(tcp) * 4;

	Connection* tmpConn = getConn(ip->ip_src, ip->ip_dst, &tcp->th_sport, &tcp->th_dport, &tcp->th_seq);

	/* Prepare packet data struct */
	sendData sd;
	sd.totalSize           = header->len;
	sd.ipSize              = ipSize;
	sd.ipHdrLen            = ipHdrLen;
	sd.tcpHdrLen           = tcpHdrLen;
	sd.tcpOptionLen        = tcpHdrLen - 20;
	sd.data.payloadSize    = static_cast<uint16_t>(sd.totalSize - (ipHdrLen + tcpHdrLen + link_layer_header_size));
	sd.data.tstamp_pcap    = header->ts;
	sd.data.seq_absolute   = ntohl(tcp->th_seq);
	sd.data.seq            = tmpConn->getRelativeSequenceNumber(sd.data.seq_absolute, RELSEQ_SEND_OUT);
	sd.data.endSeq         = sd.data.seq + sd.data.payloadSize;
	sd.data.retrans        = false;
	sd.data.is_rdb         = false;
	sd.data.sacks          = false;
	sd.data.rdb_end_seq    = 0;
	sd.data.flags          = tcp->th_flags;
	sd.data.tstamp_tcp      = 0;
	sd.data.tstamp_tcp_echo = 0;

	uint32_t payloadSize = ipSize - (ipHdrLen + tcpHdrLen); // This gives incorrect result on some packets where the ipSize is wrong (0 in a test trace)
	if (sd.data.payloadSize != payloadSize) {
		if (DEBUGL_SENDER(1) && GlobOpts::print_payload_mismatch_warn) {
			colored_fprintf(stderr, RED, "Found invalid packet length value in IP header of sender trace:\n");
			fprintf(stderr, "%s: (seq: %s): Length reported as %d, but correct value is %d.\n", tmpConn->getConnKey().c_str(),
					tmpConn->rm->absolute_seq_pair_str(sd.data.seq, sd.data.endSeq).c_str(),
					ipSize, sd.totalSize - link_layer_header_size);
			if (GlobOpts::debugLevel == 1) {
				fprintf(stderr, "Enable debug mode>=2 to show further header mismatch warnings.\n");
				GlobOpts::print_payload_mismatch_warn = false;
			}
		}
	}

	assert(sd.tcpOptionLen <= 40 && "TCP option length is too large!");

	if (sd.data.seq == std::numeric_limits<ulong>::max()) {
		if (tmpConn->closed) {
			// Probably closed due to port reuse
		}
		else {
			if (sd.data.flags & TH_SYN) {
				fprintf(stderr, "Found invalid sequence number (%u) in beginning of sender trace. Probably old SYN packets (Conn: %s)\n",
						sd.data.seq_absolute, tmpConn->getConnKey().c_str());
				return;
			}
			fprintf(stderr, "Found invalid sequence number (%u) in beginning of sender trace. "
					"Probably the sender trace has retransmissions of packets before the first packet in trace (Conn: %s)\n",
					sd.data.seq_absolute, tmpConn->getConnKey().c_str());
		}
		return;
	}

	if (first_sent_time.tv_sec == 0 && first_sent_time.tv_usec == 0) {
		first_sent_time = header->ts;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	parseTCPOptions(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + link_layer_header_size + ipHdrLen + tcpHdrLen);

	if (GlobOpts::look_for_get_request)
		look_for_get_request(header, data, link_layer_header_size);

	sentPacketCount++;
	sentBytesCount += sd.data.payloadSize;

	/*
	printf("Conn: %s : %s (%llu) (%s)\n", tmpConn->getConnKey().c_str(),
		   relative_seq_pair_str(tmpConn->rm, sd.data.seq, sd.data.endSeq).c_str(),
		   (sd.data.endSeq - sd.data.seq), get_TCP_flags_str(sd.data.flags).c_str());
	*/

	if (sd.data.payloadSize > max_payload_size) {
		max_payload_size = sd.data.payloadSize;
	}

	if (tmpConn->registerSent(&sd)) {
		tmpConn->registerRange(&sd);

		if (GlobOpts::withThroughput) {
			tmpConn->registerPacketSize(first_sent_time, header->ts, header->len, sd.data.payloadSize);
		}
	}
}



/* Process incoming ACKs */
void Dump::processAcks(const pcap_pkthdr* header, const u_char *data, u_int link_layer_header_size) {
	static const sniff_ip *ip; /* The IP header */
	static const sniff_tcp *tcp; /* The TCP header */
	static u_int ipHdrLen;
	static seq32_t ack;
	//static u_long eff_win;        /* window after scaling */
	static bool ret;
	ip = (sniff_ip*) (data + link_layer_header_size);
	ipHdrLen = IP_HL(ip) * 4;
	tcp = (sniff_tcp*) (data + link_layer_header_size + ipHdrLen);

	static u_int tcpHdrLen;
	static uint tcpOptionLen;
	tcpHdrLen = TH_OFF(tcp) * 4;
	tcpOptionLen = tcpHdrLen - 20;

	Connection *tmpConn = getConn(ip->ip_dst, ip->ip_src, &tcp->th_dport, &tcp->th_sport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		cerr << "Ack for unregistered connection found. Ignoring. Conn: " << makeConnKey(ip->ip_src, ip->ip_dst, &tcp->th_sport, &tcp->th_dport) << endl;
		return;
	}
	ack = ntohl(tcp->th_ack);

	DataSeg seg;
	memset(&seg, 0, sizeof(DataSeg));
	seg.ack         = tmpConn->getRelativeSequenceNumber(ack, RELSEQ_SEND_ACK);
	seg.tstamp_pcap = header->ts;
	seg.window = ntohs(tcp->th_win);
	seg.flags  = tcp->th_flags;

	if (seg.ack == std::numeric_limits<ulong>::max()) {
		if (tmpConn->closed) {
			// Probably closed due to port reuse
		}
		else {
			dclfprintf(stderr, DSENDER, 1, RED, "Invalid sequence number for ACK(%u)! (SYN=%d) on connection: %s\n",
					   ack, !!(seg.flags & TH_SYN), tmpConn->getConnKey().c_str());
		}
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	parseTCPOptions(&seg, opt, tcpOptionLen, tmpConn, RELSEQ_SEND_ACK);

	ret = tmpConn->registerAck(&seg);
	if (!ret) {
		if (GlobOpts::validate_ranges) {
			if (DEBUGL_SENDER(1)) {
				dclfprintf(stderr, DSENDER, 1, RED, "Failed to register ACK(%llu) on connection: %s\n", seg.ack, tmpConn->getConnKey().c_str());
			}
		}
	}
	else {
		tmpConn->lastLargestAckSeqAbsolute = ack;
		tmpConn->lastLargestAckSeq = seg.ack;
	}
	ackCount++;
}

/* Analyse receiver dump */
void Dump::processRecvd(string recvFn) {
	int packetCount = 0;
	string tmpSrcIp = filterSrcIp;
	string tmpDstIp = filterDstIp;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_pkthdr h;
	const u_char *data;

	if (DEBUGL_SENDER(1)) {
		colored_printf(YELLOW, "Processing receiver trace...\n");
	}

	if (!GlobOpts::sendNatIP.empty()) {
		tmpSrcIp = GlobOpts::sendNatIP;
		dfprintf(stderr, DRECEIVER, 1, "Sender side NATing handled. srcIp: %s, tmpSrcIp: %s\n",
				 filterSrcIp.c_str(), tmpSrcIp.c_str());
	}

	if (!GlobOpts::recvNatIP.empty()) {
		tmpDstIp = GlobOpts::recvNatIP;
		dfprintf(stderr, DRECEIVER, 1, "Receiver side NATing handled. filterDstIp: %s, tmpDstIp: %s\n",
				 filterDstIp.c_str(), tmpDstIp.c_str());
	}

	pcap_t *fd = pcap_open_offline(recvFn.c_str(), errbuf);
	if (fd == NULL) {
		cerr << "pcap: Could not open file: " << recvFn << endl;
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	int type = pcap_datalink(fd);
	u_int link_layer_header_size;

	switch (type) {
	case DLT_EN10MB: {
		link_layer_header_size = SIZE_ETHERNET;
		break;
	}
	case DLT_LINUX_SLL: {
		link_layer_header_size = SIZE_HEADER_LINUX_COOKED_MODE;
		break;
	}
	default: {
		fprintf(stderr, "Unsupported link layer type: %d ('%s')\n", type, pcap_datalink_val_to_name(type));
		exit(1);
	}
	}


	/* Set up pcap filter to include only incoming tcp
	   packets with correct IP and port numbers.
	   We exclude packets with no TCP payload. */
	bpf_program compFilter;
	stringstream filterExp;

	bool src_port_range = !isNumeric(filterSrcPort.c_str(), 10);
	bool dst_port_range = !isNumeric(filterDstPort.c_str(), 10);

	filterExp.str("");
	filterExp << "tcp";
	if (!tmpSrcIp.empty())
		filterExp << " && src host " << tmpSrcIp;
	if (!tmpDstIp.empty())
		filterExp << " && dst host " << tmpDstIp;
	if (!filterTCPIp.empty())
		filterExp << " && host " << filterTCPIp;

	if (!filterSrcPort.empty())
		filterExp << " && src " << (src_port_range ? "portrange " : "port ") << filterSrcPort;
	if (!filterDstPort.empty())
		filterExp << " && dst " << (dst_port_range ? "portrange " : "port ") << filterDstPort;

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

	if (DEBUGL_SENDER(1)) {
		printf("Using filter: '%s'\n", filterExp.str().c_str());
	}

	/* Sniff each sent packet in pcap tracefile: */
	do {
		data = (const u_char *) pcap_next(fd, &h);
		if (data == NULL) {
			if (packetCount == 0) {
				fprintf(stderr, "No packets found in trace!\n");
			}
			//pcap_perror(fd, errMsg);
		} else {
			processRecvd(&h, data, link_layer_header_size); /* Sniff packet */
			packetCount++;
		}
	} while(data != NULL);

	pcap_close(fd);

	if (DEBUGL_SENDER(1)) {
		printf("Finished processing receiver trace...\n");
	}
}

/* Process packets */
void Dump::processRecvd(const pcap_pkthdr* header, const u_char *data, u_int link_layer_header_size) {
	//const sniff_ethernet *ethernet; /* The ethernet header */
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	Connection *tmpConn;

    /* Finds the different headers+payload */
//  ethernet = (sniff_ethernet*)(data);
	ip = (sniff_ip*) (data + link_layer_header_size);
	u_int ipSize = ntohs(ip->ip_len);
	u_int ipHdrLen = IP_HL(ip)*4;
	tcp = (sniff_tcp*) (data + link_layer_header_size + ipHdrLen);
	u_int tcpHdrLen = TH_OFF(tcp)*4;

	in_addr srcIpAddr = ip->ip_src;
	in_addr dstIpAddr = ip->ip_dst;

	if (!GlobOpts::sendNatIP.empty()) {
		srcIpAddr = strToIp(filterSrcIp);
	}

	if (!GlobOpts::recvNatIP.empty()) {
		dstIpAddr = strToIp(filterDstIp);
	}

	tmpConn = getConn(srcIpAddr, dstIpAddr, &tcp->th_sport, &tcp->th_dport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		static bool warning_printed = false;
		if (warning_printed == false) {
			cerr << "Connection found in recveiver trace that does not exist in sender: " << makeConnKey(ip->ip_src, ip->ip_dst, &tcp->th_sport, &tcp->th_dport);
			cerr << ". Maybe NAT is in effect?" << endl;
			warn_with_file_and_linenum(__FILE__, __LINE__);
			warning_printed = true;
		}
		return;
	}

	if (tmpConn->lastLargestRecvEndSeq == 0 &&
		ntohl(tcp->th_seq) != tmpConn->rm->firstSeq) {
	    if (tcp->th_flags & TH_SYN) {
			if (DEBUGL_RECEIVER(1)) {
				fprintf(stderr, "Invalid sequence number in SYN packet. This is probably an old connection - discarding...\n");
			}
			return;
		}
	}

	/* Prepare packet data struct */
	sendData sd;
	sd.totalSize         = header->len;
	sd.ipSize            = ipSize;
	sd.ipHdrLen          = ipHdrLen;
	sd.tcpHdrLen         = tcpHdrLen;
	sd.tcpOptionLen      = tcpHdrLen - 20;
	sd.data.payloadSize  = static_cast<uint16_t>(sd.totalSize - (ipHdrLen + tcpHdrLen + link_layer_header_size));
	sd.data.seq_absolute = ntohl(tcp->th_seq);
	sd.data.seq          = tmpConn->getRelativeSequenceNumber(sd.data.seq_absolute, RELSEQ_RECV_INN);
	sd.data.endSeq       = sd.data.seq + sd.data.payloadSize;
	sd.data.tstamp_pcap  = header->ts;
	sd.data.is_rdb       = false;
	sd.data.sacks        = false;
	sd.data.rdb_end_seq  = 0;
	sd.data.retrans      = 0;
	sd.data.in_sequence  = 0;
	sd.data.flags        = tcp->th_flags;
	sd.data.window       = ntohs(tcp->th_win);
	sd.data.tstamp_tcp      = 0;
	sd.data.tstamp_tcp_echo = 0;

	uint32_t payloadSize = ipSize - (ipHdrLen + tcpHdrLen); // This gives incorrect result on some packets where the ipSize is wrong (0 in a test trace)
	if (sd.data.payloadSize != payloadSize) {
		if (DEBUGL_RECEIVER(1) && GlobOpts::print_payload_mismatch_warn) {
			colored_fprintf(stderr, RED, "Found invalid packet length value in IP header in receiver trace:\n");
			fprintf(stderr, "%s: (seq: %s): Length reported as %d, but correct value is %d.\n", tmpConn->getConnKey().c_str(),
					tmpConn->rm->absolute_seq_pair_str(sd.data.seq, sd.data.endSeq).c_str(),
					ipSize, sd.totalSize - link_layer_header_size);
			if (GlobOpts::debugLevel == 1) {
				fprintf(stderr, "Enable debug mode>=2 to show further header mismatch warnings.\n");
				GlobOpts::print_payload_mismatch_warn = false;
			}
		}
	}

	if (sd.data.seq == std::numeric_limits<ulong>::max()) {
		if (sd.data.flags & TH_SYN) {
			if (DEBUGL_RECEIVER(1)) {
				fprintf(stderr, "Found invalid sequence numbers in beginning of receive trace. Probably an old SYN packet (Conn: %s)\n",
						tmpConn->getConnKey().c_str());
			}
			return;
		}

		if (tmpConn->lastLargestRecvEndSeq == 0) {
			if (DEBUGL_RECEIVER(1)) {
				fprintf(stderr, "Found invalid sequence numbers in beginning of receive trace. "
						"Probably the sender tcpdump didn't start in time to save this packets (Conn: %s)\n",
						tmpConn->getConnKey().c_str());
			}
		}
		else {
			if (DEBUGL_RECEIVER(1)) {
				fprintf(stderr, "Found invalid sequence number in received data!: %u -> %llu\n", sd.data.seq_absolute, sd.data.seq);
			}
		}
		return;
	}

	uint8_t* opt = (uint8_t*) tcp + 20;
	parseTCPOptions(&sd.data, opt, sd.tcpOptionLen);

	/* define/compute tcp payload (segment) offset */
	//sd.data.data = (u_char *) (data + link_layer_header_size + ipHdrLen + tcpHdrLen);
	recvPacketCount++;
	recvBytesCount += sd.data.payloadSize;

	if (GlobOpts::look_for_get_request)
		look_for_get_request(header, data, link_layer_header_size);

	tmpConn->registerRecvd(&sd);
}

void Dump::calculateSojournTime() {

	std::ifstream file(GlobOpts::sojourn_time_file);
	std::string line;

	string time;
	string k_time;
	string sender;
	string receiver;
	string size;
	string seq, seq2, seq3;

	string sender_ip;
	string sender_port;
	string receiver_ip;
	string receiver_port;
	Connection *tmpConn;

	if (DEBUGL_SENDER(1)) {
		colored_printf(YELLOW, "Processing input data for sojourn calculation...\n");
	}

	while (std::getline(file, line)) {
		std::stringstream   linestream(line);

		//2.249093530 193315.745873965 10.0.0.12:22000 10.0.0.22:5000 50 3786484797 3786484797 3786484747 10 2147483647 5792 303585 29312 607170 911 1 0
		linestream >> time >> k_time >> sender >> receiver >> size >> seq2 >> seq >> seq3;
		//linestream >> time >> k_time >> sender >> receiver >> size >> seq >> seq2;

		sender_ip = sender.substr(0, sender.find(":"));
		sender_port = sender.substr(sender.find(":") + 1);
		receiver_ip = receiver.substr(0, receiver.find(":"));
		receiver_port = receiver.substr(receiver.find(":") + 1);

		try {
			tmpConn = getConn(sender_ip, receiver_ip, sender_port, receiver_port);
		}
		catch (const std::invalid_argument ia) {
			cout << "An exception occurred. Exception Nr. " << ia.what() << '\n';
			fprintf(stderr, "Invalid input values: Sender IP: '%s', Sender PORT: '%s', Receiver IP: '%s', Receiver PORT: '%s'\n",
					sender_ip.c_str(), receiver_ip.c_str(), sender_port.c_str(), receiver_port.c_str());
			continue;
		}

		if (tmpConn == NULL) {
			colored_printf(YELLOW, "Failed to map input to connection: time: %s, k_time: %s, sender: %s:%s, receiver: %s:%s\n",
						   time.c_str(), k_time.c_str(),
						   sender_ip.c_str(), sender_port.c_str(), receiver_ip.c_str(), receiver_port.c_str()
				);
			continue;
		}

		seq32_t tmp1 = static_cast<seq32_t>(std::stoul(seq));
		seq32_t tmp2 = static_cast<seq32_t>(std::stoul(seq2));

		DataSeg tmpSeg;
		tmpSeg.seq_absolute = max(tmp1, tmp2);
		tmpSeg.seq = tmpConn->getRelativeSequenceNumber(tmpSeg.seq_absolute, RELSEQ_SOJ_SEQ);
		tmpSeg.payloadSize = static_cast<uint16_t>(std::stoul(size));
		tmpSeg.endSeq       = tmpSeg.seq + tmpSeg.payloadSize;
		tmpSeg.tstamp_pcap.tv_sec = std::stoi(k_time.substr(0, k_time.find(".")));
		tmpSeg.tstamp_pcap.tv_usec = std::stoi(k_time.substr(k_time.find(".") + 1)) / 1000;

		/*
		if (seq != seq2) {
			colored_printf(YELLOW, "seq(%s) != seq2(%s), seq3(%s) (RelSeq: %llu)\n", seq.c_str(), seq2.c_str(), seq3.c_str(), tmpSeg.seq);
		}
		*/

		try {
			bool ret = tmpConn->rm->insertByteRange(tmpSeg.seq, tmpSeg.endSeq, INSERT_SOJOURN, &tmpSeg, 0);
			if (!ret) {
				break;
			}
		}
		catch (const std::logic_error ia) {
			cout << "An exception occurred. Exception Nr. " << ia.what() << '\n';
			printf("Invalid input values: Sender IP: '%s', Sender PORT: '%s', Receiver IP: '%s', Receiver PORT: '%s'\n",
				   sender_ip.c_str(), receiver_ip.c_str(), sender_port.c_str(), receiver_port.c_str());
			printf("Offending input line '%s'\n", line.c_str());
			throw;
		}
	}

	if (DEBUGL_SENDER(1)) {
		printf("Finished processing input data for sojourn calculation...\n");
	}
}


void Dump::calculateRetransAndRDBStats() {
	for (auto& it : conns) {
		it.second->calculateRetransAndRDBStats();
	}
}

void Dump::printPacketDetails() {
	for (auto& it : conns) {
		it.second->rm->printPacketDetails();
	}
}

void Dump::calculateLatencyVariation() {
	for (auto& it : conns) {
		it.second->calculateLatencyVariation();
	}
}

static void look_for_get_request(const pcap_pkthdr* header, const u_char *data, u_int link_layer_header_size)
{
	const sniff_ip *ip; /* The IP header */
	const sniff_tcp *tcp; /* The TCP header */
	ip = (sniff_ip*) (data + link_layer_header_size);
	// u_int ipSize = ntohs(ip->ip_len);
	u_int ipHdrLen = IP_HL(ip)*4;
	tcp = (sniff_tcp*) (data + link_layer_header_size + ipHdrLen);
	u_int tcpHdrLen = TH_OFF(tcp)*4;

    u_char* ptr = (u_char *) (data + link_layer_header_size + ipHdrLen + tcpHdrLen);
    if( (ptr - data) < header->caplen )
    {
        u_int payload_len = static_cast<u_int>(header->caplen - ( ptr - data ));
        if( payload_len > 3 )
        {
            if( not strncmp( (const char*)ptr, "GET", 3 ) )
            {
                cerr << "Found get request in received data" << endl;
                cerr << "payload length=" << header->len - (link_layer_header_size + ipHdrLen + tcpHdrLen) << endl;
                for( u_int i=0; i<payload_len; i++ )
                {
                    cerr << (char)( isprint(ptr[i]) ? ptr[i] : '?' );
                }
                cerr << endl;
            }
        }
    }
}
