#include <memory>
#include <string.h>

#include "Dump.h"
#include "color_print.h"
#include "util.h"
#include "Statistics.h"


/* Methods for class Dump */
Dump::Dump(string src_ip, string dst_ip, string tcp_ip, string src_port, string dst_port, string tcp_port, string fn)
	: senderFilename(fn)
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
	, header_caplen_count(0)
{
	timerclear(&first_sent_time);
}


Dump::Dump(const vector<four_tuple_t>& connections, string fn)
	: senderFilename(fn)
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
	, header_caplen_count(0)
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


Connection* Dump::getConn(const in_addr &srcIpAddr, const in_addr &dstIpAddr, const uint16_t *srcPort, const uint16_t *dstPort, const seq32_t *seq) {
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


Connection* Dump::getConn(string &srcIpStr, string &dstIpStr, string &srcPortStr, string &dstPortStr) {
	in_addr srcIpAddr;
	in_addr dstIpAddr;

	uint16_t srcPort = htons(static_cast<uint16_t>(std::stoul(srcPortStr)));
	uint16_t dstPort = htons(static_cast<uint16_t>(std::stoul(dstPortStr)));

	if (!inet_pton(AF_INET, srcIpStr.c_str(), &srcIpAddr)) {
		colored_fprintf(stderr, COLOR_ERROR, "Failed to convert source IP '%s'\n", srcIpStr.c_str());
	}

	if (!inet_pton(AF_INET, dstIpStr.c_str(), &dstIpAddr)) {
		colored_fprintf(stderr, COLOR_ERROR, "Failed to convert destination IP '%s'\n", srcIpStr.c_str());
	}
	return getConn(srcIpAddr, dstIpAddr, &srcPort, &dstPort, NULL);
}


/* Traverse the pcap dump and call methods for processing the packets
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender() {
	int packetCount = 0;
	PcapParse parsePkt;
	parsePkt.openPcap(senderFilename);

	stringstream filterExp;
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

	vbprintf(1, "Using pcap filter expression: '%s'\n", filterExp.str().c_str());

	/* Filter to get outgoing packets */
	parsePkt.setPcapFilter(filterExp);

	vbclprintf(1, COLOR_INFO, "Processing sent packets...\n");

	/* Sniff each sent packet in pcap tracefile: */
	do {
		parsePkt.data = (u_char *) pcap_next(parsePkt.fd, &parsePkt.header);
		if (parsePkt.data == NULL) {
			//char errMsg[50];
			//sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(fd, errMsg);
		} else {
			processSent(parsePkt); /* Sniff packet */
			packetCount++;
		}
	} while (parsePkt.data != NULL);

	vbclprintf(1, COLOR_INFO, "Finished processing sent packets...\n");

	pcap_close(parsePkt.fd);

	if (GlobOpts::validate_ranges) {
		/* DEBUG: Validate range */
		auto it_end = conns.end();
		for (auto it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
	}

	vbclprintf(1, COLOR_INFO, "Processing acknowledgements...\n");

	// Open file again but only parse ACKs
	parsePkt.openPcap(senderFilename);

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

	parsePkt.setPcapFilter(filterExp);

	packetCount = 0;
	/* Sniff each sent packet in pcap tracefile: */
	do {
		parsePkt.data = (u_char *) pcap_next(parsePkt.fd, &parsePkt.header);
		if (parsePkt.data == NULL) {
			//char errMsg[50];
			//sprintf(errMsg, "\nNo more data on file. Packets: %d\n", packetCount);
			//pcap_perror(parsePkt.fd, errMsg);
		} else {
			processAcks(parsePkt); /* Sniff packet */
			packetCount++;
		}
	} while (parsePkt.data != NULL);

	pcap_close(parsePkt.fd);

	vbclprintf(1, COLOR_INFO, "Finished processing acknowledgements...\n\n");

	if (GlobOpts::validate_ranges) {
		auto it_end = conns.end();
		for (auto it = conns.begin(); it != it_end; it++) {
			it->second->validateRanges();
		}
	}
}


/* Process outgoing packets */
void Dump::processSent(PcapParse &parsePkt) {
	parsePkt.parsePacket();
	Connection* tmpConn = getConn(parsePkt.ip->ip_src, parsePkt.ip->ip_dst, &parsePkt.tcp->th_sport, &parsePkt.tcp->th_dport, &parsePkt.tcp->th_seq);

	PcapPacket *pkt = &parsePkt.pkt;
	pkt->seg.payloadSize     = static_cast<uint16_t>(pkt->totalSize - pkt->tcpPayloadOffset);
	pkt->seg.seq             = tmpConn->getRelativeSequenceNumber(pkt->seg.seq_absolute, RELSEQ_SEND_OUT);
	pkt->seg.endSeq          = pkt->seg.seq + pkt->seg.payloadSize;

	if (pkt->seg.seq == std::numeric_limits<ulong>::max()) {
		if (tmpConn->closed) {
			// Probably closed due to port reuse
		}
		else {
			if (pkt->seg.flags & TH_SYN) {
				fprintf(stderr, "Found invalid sequence number (%u) in beginning of sender trace. Probably old SYN packets (Conn: %s)\n",
						pkt->seg.seq_absolute, tmpConn->getConnKey().c_str());
				return;
			}
			fprintf(stderr, "Found invalid sequence number (%u) in beginning of sender trace. "
					"Probably the sender trace has retransmissions of packets before the first packet in trace (Conn: %s)\n",
					pkt->seg.seq_absolute, tmpConn->getConnKey().c_str());
		}
		return;
	}

	if (first_sent_time.tv_sec == 0 && first_sent_time.tv_usec == 0) {
		first_sent_time = parsePkt.header.ts;
	}

	parsePkt.parseTCPOptions(tmpConn, RELSEQ_NONE);
	parsePkt.handlePacketParseWarnings(tmpConn, DSENDER);

	if (GlobOpts::look_for_get_request)
		look_for_get_request(parsePkt);

	sentPacketCount++;
	sentBytesCount += pkt->seg.payloadSize;

	if (pkt->seg.payloadSize > max_payload_size) {
		max_payload_size = pkt->seg.payloadSize;
	}

	if (tmpConn->registerSent(pkt)) {
		tmpConn->registerRange(&pkt->seg);

		if (GlobOpts::withThroughput) {
			tmpConn->registerPacketSize(first_sent_time, parsePkt.header.ts, parsePkt.header.len, pkt->seg.payloadSize, pkt->seg.retrans);
		}
	}
}


/* Process incoming ACKs on sender side trace */
void Dump::processAcks(PcapParse &parsePkt) {
	parsePkt.parsePacket();
	Connection *tmpConn = getConn(parsePkt.ip->ip_dst, parsePkt.ip->ip_src, &parsePkt.tcp->th_dport, &parsePkt.tcp->th_sport, NULL);
	seq32_t ack = ntohl(parsePkt.tcp->th_ack);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		cerr << "Ack for unregistered connection found. Ignoring. Conn: " << makeConnKey(parsePkt.ip->ip_src, parsePkt.ip->ip_dst, &parsePkt.tcp->th_sport, &parsePkt.tcp->th_dport) << endl;
		return;
	}

	PcapPacket *pkt = &parsePkt.pkt;
	pkt->seg.seq          = tmpConn->getRelativeSequenceNumber(pkt->seg.seq_absolute, RELSEQ_SEND_OUT);
	pkt->seg.ack          = tmpConn->getRelativeSequenceNumber(ack, RELSEQ_SEND_ACK);

	if (pkt->seg.ack == std::numeric_limits<ulong>::max()) {
		if (tmpConn->closed) {
			// Probably closed due to port reuse
		}
		else {
			dclfprintf(stderr, DSENDER, 1, COLOR_ERROR, "Invalid sequence number for ACK(%u)! (SYN=%d) on connection: %s\n",
					   pkt->seg.ack, !!(pkt->seg.flags & TH_SYN), tmpConn->getConnKey().c_str());
		}
		return;
	}

	parsePkt.parseTCPOptions(tmpConn, RELSEQ_SEND_ACK);
	parsePkt.handlePacketParseWarnings(tmpConn, DSENDER);

	bool ret = tmpConn->registerAck(&pkt->seg);
	if (!ret) {
		if (GlobOpts::validate_ranges) {
			if (DEBUGL_SENDER(1)) {
				dclfprintf(stderr, DSENDER, 1, COLOR_ERROR, "Failed to register ACK(%llu) on connection: %s\n", pkt->seg.ack, tmpConn->getConnKey().c_str());
			}
		}
	}
	else {
		tmpConn->lastLargestAckSeqAbsolute = ack;
		tmpConn->lastLargestAckSeq = pkt->seg.ack;
	}
	ackCount++;
}


/* Analyse receiver dump */
void Dump::processRecvd(string recvFn) {
	int packetCount = 0;
	string tmpSrcIp = filterSrcIp;
	string tmpDstIp = filterDstIp;
	PcapParse parsePkt;

	dclfprintf(stderr, DRECEIVER, 1, COLOR_INFO, "Processing receiver trace...\n");

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

	parsePkt.openPcap(recvFn);

	/* Set up pcap filter to include only incoming tcp
	   packets with correct IP and port numbers.
	   We exclude packets with no TCP payload. */
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

	/* Filter to get outgoing packets */
	parsePkt.setPcapFilter(filterExp);

	vbprintf(1, "Using filter: '%s'\n", filterExp.str().c_str());

	/* Sniff each sent packet in pcap tracefile: */
	do {
		parsePkt.data = (u_char *) pcap_next(parsePkt.fd, &parsePkt.header);
		if (parsePkt.data == NULL) {
			if (packetCount == 0) {
				fprintf(stderr, "No packets found in trace!\n");
			}
		} else {
			processRecvd(parsePkt); /* Sniff packet */
			packetCount++;
		}
	} while (parsePkt.data != NULL);

	pcap_close(parsePkt.fd);

	vbclprintf(1, COLOR_INFO, "Finished processing acknowledgements...\n");
}


/* Process packets */
void Dump::processRecvd(PcapParse &parsePkt) {
	parsePkt.parsePacket();
	Connection *tmpConn;

	in_addr srcIpAddr = parsePkt.ip->ip_src;
	in_addr dstIpAddr = parsePkt.ip->ip_dst;

	if (!GlobOpts::sendNatIP.empty()) {
		srcIpAddr = strToIp(filterSrcIp);
	}

	if (!GlobOpts::recvNatIP.empty()) {
		dstIpAddr = strToIp(filterDstIp);
	}

	tmpConn = getConn(srcIpAddr, dstIpAddr, &parsePkt.tcp->th_sport, &parsePkt.tcp->th_dport, NULL);

	// It should not be possible that the connection is not yet created
	// If lingering ack arrives for a closed connection, this may happen
	if (tmpConn == NULL) {
		static bool warning_printed = false;
		if (warning_printed == false) {
			cerr << "Connection found in recveiver trace that does not exist in sender: " << makeConnKey(parsePkt.ip->ip_src, parsePkt.ip->ip_dst, &parsePkt.tcp->th_sport, &parsePkt.tcp->th_dport);
			cerr << ". Maybe NAT is in effect?" << endl;
			warn_with_file_and_linenum(__FILE__, __LINE__);
			warning_printed = true;
		}
		return;
	}

	if (tmpConn->lastLargestRecvEndSeq == 0 &&
		ntohl(parsePkt.tcp->th_seq) != tmpConn->rm->firstSeq) {
		if (parsePkt.tcp->th_flags & TH_SYN) {
			dfprintf(stderr, DRECEIVER, 1, "Invalid sequence number in SYN packet. This is probably an old connection - discarding...\n");
			return;
		}
	}

	PcapPacket *pkt = &parsePkt.pkt;
	pkt->seg.payloadSize  = static_cast<uint16_t>(pkt->totalSize - pkt->tcpPayloadOffset);
	pkt->seg.seq          = tmpConn->getRelativeSequenceNumber(pkt->seg.seq_absolute, RELSEQ_RECV_INN);
	pkt->seg.endSeq       = pkt->seg.seq + pkt->seg.payloadSize;

	if (pkt->seg.seq == std::numeric_limits<ulong>::max()) {
		if (pkt->seg.flags & TH_SYN) {
			dclfprintf(stderr, DRECEIVER, 1, COLOR_NOTICE, "Found invalid sequence numbers in beginning of receive trace. Probably an old SYN packet (Conn: %s)\n",
					 tmpConn->getConnKey().c_str());
			return;
		}
		if (tmpConn->lastLargestRecvEndSeq == 0) {
			dclfprintf(stderr, DRECEIVER, 1, COLOR_NOTICE, "Found invalid sequence numbers in beginning of receive trace. "
					   "Probably the sender tcpdump didn't start in time to save this packets (Conn: %s)\n",
					   tmpConn->getConnKey().c_str());
		}
		else {
			dclfprintf(stderr, DRECEIVER, 1, COLOR_NOTICE, "Found invalid sequence number in received data!: %u -> %llu\n", pkt->seg.seq_absolute, pkt->seg.seq);
		}
		return;
	}

	parsePkt.parseTCPOptions(tmpConn, RELSEQ_NONE);
	parsePkt.handlePacketParseWarnings(tmpConn, DRECEIVER);

	recvPacketCount++;
	recvBytesCount += pkt->seg.payloadSize;

	if (GlobOpts::look_for_get_request)
		look_for_get_request(parsePkt);

	tmpConn->registerRecvd(&pkt->seg);
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

	dclprintf(DSENDER, 1, COLOR_INFO, "Processing input data for sojourn calculation...\n");

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
			colored_printf(COLOR_WARN, "Failed to map input to connection: time: %s, k_time: %s, sender: %s:%s, receiver: %s:%s\n",
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

		try {
			bool ret = tmpConn->rm->insertByteRange(tmpSeg.seq, tmpSeg.endSeq, INSERT_SOJOURN, &tmpSeg, 0);
			if (!ret) {
				break;
			}
		} catch (const std::logic_error ia) {
			cout << "An exception occurred. Exception Nr. " << ia.what() << '\n';
			printf("Invalid input values: Sender IP: '%s', Sender PORT: '%s', Receiver IP: '%s', Receiver PORT: '%s'\n",
				   sender_ip.c_str(), receiver_ip.c_str(), sender_port.c_str(), receiver_port.c_str());
			printf("Offending input line '%s'\n", line.c_str());
			throw;
		}
	}
	vbclprintf(1, COLOR_INFO, "Finished processing input data for sojourn calculation...\n");
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


void Dump::look_for_get_request(PcapParse &parsePkt) {
	u_char* ptr = (u_char *) (parsePkt.data + parsePkt.pkt.tcpPayloadOffset);
	if ((ptr - parsePkt.data) < parsePkt.pkt.caplen) {
		u_int payload_len = static_cast<u_int>(parsePkt.pkt.caplen - (ptr - parsePkt.data));
		if (payload_len > 3) {
			if (not strncmp((const char*)ptr, "GET", 3)) {
				cerr << "Found get request in received data" << endl;
				cerr << "payload length=" << parsePkt.header.len - (parsePkt.link_layer_header_size + parsePkt.pkt.ipHdrLen + parsePkt.pkt.tcpHdrLen) << endl;
				for (u_int i=0; i < payload_len; i++) {
					cerr << (char)( isprint(ptr[i]) ? ptr[i] : '?' );
				}
				cerr << endl;
			}
		}
	}
}
