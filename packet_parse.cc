#include "Connection.h"
#include "packet_parse.h"


string get_TCP_flags_str(u_char flags) {
	stringstream out;
	if (flags & TH_SYN)
		out << ",SYN";
	if (flags & TH_ACK)
		out << ",ACK";
	if (flags & TH_FIN)
		out << ",FIN";
	if (flags & TH_RST)
		out << ",RST";
	string result = out.str();
	if (!result.empty())
		result.erase(0, 1);
	return "[" + result + "]";;
}


string seq_pair_str(seq64_t start, seq64_t end) {
	return to_string(start) + "," + to_string(end);
}


void PcapParse::handlePacketParseWarnings(Connection *conn, enum debug_type type) {
	uint32_t payloadSize = pkt.ipSize - (pkt.ipHdrLen + pkt.tcpHdrLen); // This gives incorrect result on some packets where the ipSize is wrong (0 in a test trace)

	if (pkt.seg.payloadSize != payloadSize) {
		if (check_debug_level(type, 1) && GlobOpts::print_payload_mismatch_warn) {
			colored_fprintf(stderr, COLOR_WARN, "Found invalid packet length value in IP header of %s trace:\n", debug_type_str(type).c_str());
			fprintf(stderr, "%s: (seq: %s): Length reported as %d, but correct value is %d.\n", conn->getConnKey().c_str(),
					conn->rm->absolute_seq_pair_str(pkt.seg.seq, pkt.seg.endSeq).c_str(),
					pkt.ipSize, pkt.totalSize - link_layer_header_size);
			if (GlobOpts::debugLevel == 1) {
				fprintf(stderr, "Enable debug mode>=2 to show further header mismatch warnings.\n");
				GlobOpts::print_payload_mismatch_warn = false;
			}
		}
	}

	if (pkt.caplen < pkt.tcpPayloadOffset) {
		if (check_debug_level(type, 1) && GlobOpts::verbose > 0 && GlobOpts::print_pkt_header_caplen_truncated_warn) {
			colored_fprintf(stderr, COLOR_WARN, "Incomplete header warning in %s trace for connection %s: ",
							debug_type_str(type).c_str(), conn->getConnKey().c_str());
			fprintf(stderr, "%d bytes of packet data captured, but TCP header ends at byte %d.\n"
					"Timestamp: %ld.%ld seq: %llu, ack: %llu\n",
					pkt.caplen, pkt.tcpPayloadOffset,
					pkt.seg.tstamp_pcap.tv_sec,
					(long) pkt.seg.tstamp_pcap.tv_usec, // __darwin_suseconds_t on OSX which is int
					pkt.seg.seq, pkt.seg.ack);
			if (GlobOpts::debugLevel == 1) {
				fprintf(stderr, "Further warnings will be supressed. Enable debug mode>=2 to show all warnings.\n");
				GlobOpts::print_pkt_header_caplen_truncated_warn = false;
			}
		}
		GlobOpts::pkt_header_caplen_truncated_count++;
	}
}


/*
  Set filter on pcap input
 */
void PcapParse::setPcapFilter(stringstream &filterExp) {
	bpf_program compFilter;
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
}


void PcapParse::parsePacket() {
	ip = (sniff_ip*) (data + link_layer_header_size);
	pkt.ipHdrLen = IP_HL(ip) * 4;
	tcp = (sniff_tcp*) (data + link_layer_header_size + pkt.ipHdrLen);
	pkt.caplen = header.caplen;
	pkt.totalSize = header.len;
	pkt.ipSize = ntohs(ip->ip_len);
	pkt.tcpHdrLen = TH_OFF(tcp) * 4;
	pkt.tcpOptionLen = pkt.tcpHdrLen - 20;
	pkt.tcpPayloadOffset = link_layer_header_size + pkt.ipHdrLen + pkt.tcpHdrLen;
	// DataSeq
	pkt.seg.reset();
	pkt.seg.tstamp_pcap = header.ts;
	pkt.seg.seq_absolute = ntohl(tcp->th_seq);
	pkt.seg.flags  = tcp->th_flags;
	pkt.seg.window = ntohs(tcp->th_win);
}


void PcapParse::openPcap(string &filename) {
	char errbuf[PCAP_ERRBUF_SIZE];

	fd = pcap_open_offline(filename.c_str(), errbuf);
	if (fd == NULL) {
		colored_fprintf(stderr, COLOR_FATAL, "pcap: Failed to open file '%s': %s\n", filename.c_str(), errbuf);
		exit_with_file_and_linenum(1, __FILE__, __LINE__);
	}

	int type = pcap_datalink(fd);

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
}


bool PcapParse::parseTCPOptions(Connection* conn, relative_seq_type seq_type) {
	DataSeg* seg = &pkt.seg;
	TCPOptParser parser(this);

	ulong opt_offset = 0; // Offset into the tcp options
	void *opt_data_ptr;

	while (*parser.opts != 0 && opt_offset < pkt.tcpOptionLen) {
		tcp_option_t *_opt = (tcp_option_t*) (parser.opts + opt_offset);
		if (_opt->kind == tcp_opt_end) { /* End of options list */
			break;
		}
		if (_opt->kind == tcp_opt_nop) {  /* NOP */
			opt_offset += 1;
			continue;
		}
		if (_opt->kind == tcp_opt_timestamp) {  /* Timestamp */
			if ((opt_data_ptr = parser.getTcpOptValuePtr(opt_offset + 2, sizeof(uint32_t), _opt->kind))) {
				seg->tstamp_tcp = ntohl(*((uint32_t*) opt_data_ptr));
			} else {
				return false;
			}
			if ((opt_data_ptr = parser.getTcpOptValuePtr(opt_offset + 6, sizeof(uint32_t), _opt->kind))) {
				seg->tstamp_tcp_echo = ntohl(*((uint32_t*) opt_data_ptr));
			} else {
				return false;
			}
		}
		if (_opt->kind == tcp_opt_sack && seq_type == RELSEQ_SEND_ACK) {  /* SACK */
			// Calculate number of SACK blocks:
			// Subtract 2 (Kind field and size field) and divide by size of seq pair (2 * 4)
			ulong blocks = (_opt->size - 2) / 8;
			seg->sacks = true;
			for (ulong i = 0; i < blocks; i++) {
				seq32_t leftin, rightin;
				if ((opt_data_ptr = parser.getTcpOptValuePtr(opt_offset + 2 + (4 * blocks * i), sizeof(uint32_t), _opt->kind))) {
					leftin = ntohl(*((uint32_t*) opt_data_ptr));
				} else {
					return false;
				}

				if ((opt_data_ptr = parser.getTcpOptValuePtr(opt_offset + 6 + (4 * blocks * i), sizeof(uint32_t), _opt->kind))) {
					rightin = ntohl(*((uint32_t*) opt_data_ptr));
				} else {
					return false;
				}

				seq64_t left = conn->getRelativeSequenceNumber(leftin, RELSEQ_SEND_ACK);
				seq64_t right = conn->getRelativeSequenceNumber(rightin, RELSEQ_SEND_ACK);
				seg->addTcpSack(pair<seq64_t, seq64_t>(left, right));
			}
		}
		opt_offset += _opt->size;
	}
	return true;
}
