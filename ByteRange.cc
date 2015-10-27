#include "ByteRange.h"
#include "color_print.h"
#include "time_util.h"
#include "common.h"

bool ByteRange::matchReceivedType(RangeManager *rm, bool print) {
	if (print) {
		printf("recv timestamp: %u ", received_tstamp_tcp);
		printf("tstamps: %lu, rdb-stamps: %lu", tstamps_tcp.size(), rdb_tstamps_tcp.size());
	}
	// Find which data packet was received first
	//printf("tstamps_tcp.size(): %lu\n", tstamps_tcp.size());
	printf("Range(%s): tstamps_tcp.size(): %lu\n", seq_pair_str(rm->get_print_seq(startSeq), rm->get_print_seq(endSeq)).c_str(), tstamps_tcp.size());

	for (ulong i = 0; i < tstamps_tcp.size(); i++) {
		if (print) {
			printf("     timestamp: %u\n", tstamps_tcp[i].first);
 		}
		if (tstamps_tcp[i].first == received_tstamp_tcp) {
			send_tcp_stamp_recv_index = i; // Store the index of the send packet that matches the first received packet
			// Retrans
			if (i > 0) {
				recv_type = RETR;
				recv_type_num = i;
				return true;
			}
			// First regular TCP packet
			else {
				recv_type = DATA;
				return true;
			}
		}
	}
	for (ulong i = 0; i < rdb_tstamps_tcp.size(); i++) {
		if (print) {
			printf(" rdb_timestamp: %u\n", rdb_tstamps_tcp[i]);
		}

		if (rdb_tstamps_tcp[i] == received_tstamp_tcp) {
			recv_type = RDB;
			recv_type_num = static_cast<uint8_t>(i + 1);
			return true;
		}
	}
	if (print) {
		printf("\n");
	}
	return false;
}

void ByteRange::printTstampsTcp(ulong limit) {
	printf("recv timestamp: %u, ", received_tstamp_tcp);
	printf("tstamps_tcp count: %lu, rdb-stamps count: %lu\n", tstamps_tcp.size(), rdb_tstamps_tcp.size());

	ulong size = tstamps_tcp.size();
	if (limit > 0)
		size = std::min(size, limit);
	for (ulong i = 0; i < size; i++) {
		printf("     timestamp: %u\n", tstamps_tcp[i].first);
	}
	size = rdb_tstamps_tcp.size();
	if (limit > 0)
		size = std::min(size, limit);
	for (ulong i = 0; i < rdb_tstamps_tcp.size(); i++) {
		printf(" rdb_timestamp: %u\n", rdb_tstamps_tcp[i]);
	}
	printf("\n");
}

void ByteRange::printTstampsPcap() {
	long acktime_3 = get_usecs(&ackTime);
	printf("acked timestamp: %ld ", acktime_3);

	timeval tmp;
	long ms = 0;
	for (ulong i = 0; i < sent_tstamp_pcap.size(); i++) {
		timersub(&ackTime, &sent_tstamp_pcap[i].first, &tmp);
		ms = (tmp.tv_sec * 1000) + (tmp.tv_usec / 1000);

		long ts = 0;
		if (sent_tstamp_pcap[i].first.tv_sec > 0) {
			ts += sent_tstamp_pcap[i].first.tv_sec * 1000000;
		}
		ts += (sent_tstamp_pcap[i].first.tv_usec);
		printf("     timestamp: %lu, diff: %lu\n", ts, ms);
	}
}

bool ByteRange::addSegmentEnteredKernelTime(seq64_t seq, timeval &tv) {

	if (sent_data_pkt_pcap_index == -1) {
		//printf("sent_data_pkt_pcap_index: %hu, acked_sent: %u\n", sent_data_pkt_pcap_index, acked_sent);
		return false;
	}
	long sent = get_usecs(&(sent_tstamp_pcap[(size_t) sent_data_pkt_pcap_index].first));
	long soj = get_usecs(&tv);
	if (soj > sent) {
		char buf1[30];
		char buf2[30];
		sprint_time_us_prec(buf1, sent_tstamp_pcap[(size_t) sent_data_pkt_pcap_index].first);
		sprint_time_us_prec(buf2, tv);
		size_t print_packet_ranges_index = 0;
		//fprintf(stderr, "ByteRange seq_with_print_range() type: %d\n", sent_tstamp_pcap[sent_data_pkt_pcap_index].second);
		if (GlobOpts::print_packets_pairs.size() == 0 ||
			seqWithPrintRange(startSeq, endSeq, print_packet_ranges_index) == 1) {
			colored_printf(RED, "INSERT INCORRECT SOJOURN TIME for ByteRange(%llu, %llu)\n"
						   "Sent time '%s' is before sojourn time '%s'\n", startSeq, endSeq,
						   buf1, buf2);
			printf("Seq: %llu, startSeq: %llu, endSeq: %llu\n", seq, startSeq, endSeq);
		}
		return false;
	}
	sojourn_time = 1;
	sojourn_tstamps.push_back(pair<seq64_t, timeval>(seq, tv));
	return true;
}

/* Get the difference between send and ack time for this range
   Return: Time difference in microseconds
 */
long ByteRange::getSendAckTimeDiff(RangeManager *rm) {
	timeval tv_diff;
	long usec = 0;

	if (sent_tstamp_pcap.empty() || (sent_tstamp_pcap[0].first.tv_sec == 0 && sent_tstamp_pcap[0].first.tv_usec == 0)) {
#ifdef DEBUG
		cerr << "Range without a send time. Skipping: " << endl;
#endif
		return 0;
	}

	if (ackTime.tv_sec == 0 && ackTime.tv_usec == 0) {
		// If equals, they're syn or acks
		if (startSeq != endSeq) {
			multimap<seq64_t, ByteRange*>::reverse_iterator it, it_end = rm->ranges.rend();
			int count = 0;
			// Goes through all the packets from the end
			// If all the packets after this packet has no ack time, then we presume it's caused by the
			// ack not being received before tcpdump was killed
			for (it = rm->ranges.rbegin(); it != it_end; it++) {
				if (!(it->second->ackTime.tv_sec == 0 && it->second->ackTime.tv_usec == 0))
					break;
				if (it->second->getStartSeq() == startSeq && it->second->getEndSeq() == endSeq) {
					if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
						fprintf(stderr, "Range with no ACK time. This packet is at the end of the stream (%dth last), so we presume" \
								" this is caused by tcpdump being killed before the packets were acked.\n", count);
					}
					return 0;
				}
				count++;
			}
			colored_printf(RED, "Range(%llu, %llu) has no ACK time. This shouldn't really happen... Packet is %d before last packet\n", startSeq, endSeq, count);
		}
		return 0;
	}

	/* since ackTime will always be bigger than sent_tstamp_pcap,
	   (directly comparable timers) timerSub can be used here */
	timersub(&ackTime, &sent_tstamp_pcap[0].first, &tv_diff);
	usec = get_usecs(&tv_diff);

	if (usec < 0) { /* Should not be possible */
		colored_fprintf(stderr, RED, "Found byte with negative latency (%d usec)\n", usec);
		string s = this->strInfo();
		cout << s;
		assert(0);
	}

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "Latency for range: " << usec << endl;
		if (usec > 1000000 || usec < 10000) {
			cerr << "Strange latency: " << usec << "usec." << endl;
			//cerr << "Start seq: " << rm->relative_seq(startSeq) << " End seq: " << rm->relative_seq(endSeq) << endl;
			cerr << "Size of range: " << endSeq - startSeq << endl;
			cerr << "sent_tstamp_pcap.tv_sec: " << sent_tstamp_pcap[0].first.tv_sec << " - sent_tstamp_pcap.tv_usec: "
				 << sent_tstamp_pcap[0].first.tv_usec << endl;
			cerr << "ackTime.tv_sec : " << ackTime.tv_sec << "  - ackTime.tv_usec : "
				 << ackTime.tv_usec << endl;
			cerr << "Number of retransmissions: " << packet_retrans_count << endl;
			cerr << "Number of bundles: " << rdb_count << endl;
		}
	}
	return (int) usec;
}

vector< pair<int, int> > ByteRange::getSojournTimes() {
	timeval tv_diff;
	vector< pair<int, int> > sojourn_times;
	long usec = 0;

	if (sent_tstamp_pcap.empty() || (sent_tstamp_pcap[0].first.tv_sec == 0 && sent_tstamp_pcap[0].first.tv_usec == 0)) {
#ifdef DEBUG
		cerr << "Range without a send time. Skipping: " << endl;
#endif
		sojourn_times.push_back(pair<int, int>(0, 0));
		return sojourn_times;
	}

	if (!sojourn_time) {
		//printf("SOJOURN RETURN sojourn_time: %d, stamp: %ld.%ld\n", sojourn_time, tval_pair(sojourn_tstamp));
		sojourn_times.push_back(pair<int, int>(0, 0));
		return sojourn_times;
	}

	ulong send_tstamp_index = 0;
	for (ulong i = 0; i < sent_tstamp_pcap.size(); i++) {
		send_tstamp_index = i;
		if (sent_tstamp_pcap[i].second == ST_PKT)
			break;
	}

	if (sent_tstamp_pcap[send_tstamp_index].second != ST_PKT) {
		printf("Using sent time for packet type: %d ??\n", sent_tstamp_pcap[send_tstamp_index].second);
	}

	seq64_t tmpBeginSeq = startSeq;
	for (ulong i = 0; i < sojourn_tstamps.size(); i++) {
		timersub(&sent_tstamp_pcap[send_tstamp_index].first, &sojourn_tstamps[i].second, &tv_diff);
		usec = get_usecs(&tv_diff);
		if (usec < 0) { /* Should not be possible */
			colored_fprintf(stderr, RED, "Found ByteRange with negative sojourn latency (%d usec).\n", usec);
			cout << this->strInfo();
			//assert(0);
		}
		sojourn_times.push_back(pair<int, int>(sojourn_tstamps[i].first - tmpBeginSeq, usec));
		tmpBeginSeq = sojourn_tstamps[i].first;
	}

	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "Latency for range: " << usec << endl;
		if (usec > 1000000 || usec < 10000) {
			cerr << "Strange latency: " << usec << "usec." << endl;
			//cerr << "Start seq: " << rm->relative_seq(startSeq) << " End seq: " << rm->relative_seq(endSeq) << endl;
			cerr << "Size of range: " << endSeq - startSeq << endl;
			cerr << "sent_tstamp_pcap.tv_sec: " << sent_tstamp_pcap[0].first.tv_sec << " - sent_tstamp_pcap.tv_usec: "
				 << sent_tstamp_pcap[0].first.tv_usec << endl;
			cerr << "ackTime.tv_sec : " << ackTime.tv_sec << "  - ackTime.tv_usec : "
				 << ackTime.tv_usec << endl;
			cerr << "Number of retransmissions: " << packet_retrans_count << endl;
			cerr << "Number of bundles: " << rdb_count << endl;
		}
	}
	return sojourn_times;
}

void ByteRange::calculateRecvDiff(timeval *recv_tstamp) {
	timeval tv;
	long ms = 0;
	if (recv_tstamp == NULL) {
		recv_tstamp = &received_tstamp_pcap;
	}
	/* Use own macro in order to handle negative diffs */
	negtimersub(recv_tstamp, &sent_tstamp_pcap[send_tcp_stamp_recv_index].first, &tv);

	ms += tv.tv_sec * 1000;
	if (ms >= 0)
		ms += (tv.tv_usec / 1000);
	else
		ms -= (tv.tv_usec / 1000);
	diff = ms;
}

string ByteRange::str() {
	stringstream s;
	s << "ByteRange(" << startSeq << ", " << endSeq << ")" << endl;
	return s.str();
}

string ByteRange::strInfo() {
	stringstream s;
	s << "ByteRange(" << startSeq << ", " << endSeq << ")" << endl;
	s << "size: " << byte_count << endl;
	s << "sent_tstamp: " << sent_tstamp_pcap[0].first.tv_sec << "."  << sent_tstamp_pcap[0].first.tv_usec  << endl;
	s << "ackTime:     " << ackTime.tv_sec << "." << ackTime.tv_usec  << endl;

	//if (sojourn_time)
	//	s << "sojournTime: " << sojourn_tstamp.tv_sec << "." << sojourn_tstamp.tv_usec  << endl;

	s << "syn: " << std::to_string(syn) << ", fin:" << std::to_string(fin) << ", rst: " << std::to_string(rst) << endl;

	for (ulong i = 0; i < tstamps_tcp.size(); i++) {
		s << "tcp tstamp:" << tstamps_tcp[i].first << endl;
	}

/*
  cerr << endl << "-------RangePrint-------" << endl;
  cerr << "startSeq   : " << rm->relative_seq(startSeq) << endl;
  cerr << "endSeq     : " << rm->relative_seq(endSeq) << endl;
  cerr << "sendTime   : " << sendTime.tv_sec << "." << sendTime.tv_usec << endl;
  cerr << "ackTime    : " << ackTime.tv_sec << "." << ackTime.tv_usec << endl;
  cerr << "recvTime   : " << recvTime.tv_sec << "." << recvTime.tv_usec << endl;
  cerr << "acked      : " << acked << endl;
  cerr << "numRetrans : " << numRetrans << endl;;
  cerr << "numBundled : " << numBundled << endl;
  cerr << "diff       : " << diff << endl;
  cerr << "dcDiff     : " << dcDiff << endl << endl;;
*/
	return s.str();
}

timeval* ByteRange::getSendTime() {
	if (sent_tstamp_pcap[0].first.tv_sec == 0 && sent_tstamp_pcap[0].first.tv_usec == 0)
		return NULL;
	else
		return &sent_tstamp_pcap[0].first;
}

timeval* ByteRange::getAckTime() {
	if (ackTime.tv_sec == 0 && ackTime.tv_usec == 0)
		return NULL;
	else
		return &ackTime;
}

timeval* ByteRange::getRecvTime() {
	if (received_tstamp_pcap.tv_sec == 0 && received_tstamp_pcap.tv_usec == 0)
		return NULL;
	else
		return &received_tstamp_pcap;
}
