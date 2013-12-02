#include "ByteRange.h"
#include "color_print.h"

const char *received_type_str[] = {"DEF", "DTA", "RDB", "RTR"};

bool ByteRange::match_received_type() {
	return match_received_type(false);
}

bool ByteRange::match_received_type(bool print) {
	if (print) {
		printf("recv timestamp: %u ", received_tstamp_tcp);
		printf("tstamps: %lu, rdb-stamps: %lu", tstamps_tcp.size(), rdb_tstamps_tcp.size());
	}
	// Find which data packet was received first
	for (ulong i = 0; i < tstamps_tcp.size(); i++) {
		if (print) {
			printf("     timestamp: %u\n", tstamps_tcp[i]);
		}
		if (tstamps_tcp[i] == received_tstamp_tcp) {
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
			recv_type_num = i + 1;
			return true;
		}
	}
	if (print) {
		printf("\n");
	}
	return false;
}

void ByteRange::print_tstamps_tcp() {
	printf("recv timestamp: %u ", received_tstamp_tcp);
	printf("tstamps_tcp: %lu, rdb-stamps: %lu\n", tstamps_tcp.size(), rdb_tstamps_tcp.size());

	for (ulong i = 0; i < tstamps_tcp.size(); i++) {
		printf("     timestamp: %u\n", tstamps_tcp[i]);
	}
	for (ulong i = 0; i < rdb_tstamps_tcp.size(); i++) {
		printf(" rdb_timestamp: %u\n", rdb_tstamps_tcp[i]);
	}
	printf("\n");
}

void ByteRange::print_tstamps_pcap() {
	ulong acktime_3 = ackTime.tv_sec * 1000000 + ackTime.tv_usec;
	printf("acked timestamp: %lu ", acktime_3);

	timeval tmp;
	ulong ms = 0;
	for (ulong i = 0; i < sent_tstamp_pcap.size(); i++) {
		timersub(&ackTime, &sent_tstamp_pcap[i], &tmp);
		ms = (tmp.tv_sec * 1000) + (tmp.tv_usec / 1000);

		ulong ts = 0;
		if (sent_tstamp_pcap[i].tv_sec > 0) {
			ts += sent_tstamp_pcap[i].tv_sec * 1000000;
		}
		ts += (sent_tstamp_pcap[i].tv_usec);
		printf("     timestamp: %lu, diff: %lu\n", ts, ms);
	}
}


/* Get the difference between send and ack time for this range */
int ByteRange::getSendAckTimeDiff(RangeManager *rm) {
  struct timeval tv;
  int ms = 0;

  if (sent_tstamp_pcap[0].tv_sec == 0 && sent_tstamp_pcap[0].tv_usec == 0) {
	  cerr << "Range without a send time. Skipping: " << endl;
	  return 0;
  }

  if (ackTime.tv_sec == 0 && ackTime.tv_usec == 0) {
	  // If equals, they're syn or acks
	  if (startSeq != endSeq) {
		  multimap<ulong, ByteRange*>::reverse_iterator it, it_end = rm->ranges.rend();
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
		  colored_printf(RED, "Range(%lu, %lu) has no ACK time. This shouldn't really happen... Packet is %d before last packet\n", startSeq, endSeq, count);
	  }
	  return 0;
  }

  /* since ackTime will always be bigger than sent_tstamp_pcap,
     (directly comparable timers) timerSub can be used here */
  timersub(&ackTime, &sent_tstamp_pcap[0], &tv);

  if (tv.tv_sec > 0) {
    ms += tv.tv_sec * 1000;
  }
  ms += (int) (tv.tv_usec / 1000);

  if (ms < 0) { /* Should not be possible */
	  cerr << "Found byte with 0ms or less latency. Exiting." << endl;
	  printf("Is acked: %d\n", acked);
	  exit(1);
  }

  if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
    cerr << "Latency for range: " << ms << endl;
    if (ms > 1000 || ms < 10) {
      cerr << "Strange latency: " << ms << "ms." << endl;
      //cerr << "Start seq: " << rm->relative_seq(startSeq) << " End seq: " << rm->relative_seq(endSeq) << endl;
      cerr << "Size of range: " << endSeq - startSeq << endl;
      cerr << "sent_tstamp_pcap.tv_sec: " << sent_tstamp_pcap[0].tv_sec << " - sent_tstamp_pcap.tv_usec: "
	   << sent_tstamp_pcap[0].tv_usec << endl;
      cerr << "ackTime.tv_sec : " << ackTime.tv_sec << "  - ackTime.tv_usec : "
	   << ackTime.tv_usec << endl;
      cerr << "Number of retransmissions: " << retrans_count << endl;
      cerr << "Number of bundles: " << rdb_count << endl;
    }
  }
  return ms;
}

void ByteRange::setDiff() {
	struct timeval tv;
	long ms = 0;
	/* Use own macro in order to handle negative diffs */
	negtimersub(&received_tstamp_pcap, &sent_tstamp_pcap[0], &tv);

	ms += tv.tv_sec * 1000;
	if(ms >= 0)
		ms += (tv.tv_usec / 1000);
	else
		ms -= (tv.tv_usec / 1000);
	diff = ms;
}

void ByteRange::printValues(){
  cerr << endl << "-------RangePrint-------" << endl;
/*
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
}

timeval* ByteRange::getSendTime(){
	if (sent_tstamp_pcap[0].tv_sec == 0 && sent_tstamp_pcap[0].tv_usec == 0)
		return NULL;
	else
		return &sent_tstamp_pcap[0];
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
