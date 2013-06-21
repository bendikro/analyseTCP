#include "Range.h"

void Range::printSEQ() {
	printf("New Range(%lu, %lu, %lu) Len: %u\n", rm->relative_seq(startSeq), rm->relative_seq(rdbSeq), rm->relative_seq(endSeq), payloadLen);
}

/* Range */
void Range::insertAckTime(timeval *tv) {
  ackTime = *tv;
  acked = true;
}

timeval* Range::getSendTime(){
  if(sendTime.tv_sec == 0 && sendTime.tv_usec == 0)
    return NULL;
  else
    return &sendTime;
}

timeval* Range::getAckTime() {
  if(ackTime.tv_sec == 0 && ackTime.tv_usec == 0)
    return NULL;
  else
    return &ackTime;
}

timeval* Range::getRecvTime() {
  if(recvTime.tv_sec == 0 && recvTime.tv_usec == 0)
    return NULL;
  else
    return &recvTime;
}

/* Get the difference between send and ack time for this range */
int Range::getDiff() {
  struct timeval tv;
  int ms = 0;

  if (isDummy()){
	if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
		cerr << "Dummy range. Skipping." << endl;
	}
	return 0;
  }

  if (sendTime.tv_sec == 0 && sendTime.tv_usec == 0) {
	  cerr << "Range without a send time. Skipping: ";
	  printf("%lu - %lu - %lu\n", rdbSeq, startSeq, endSeq);
    return 0;
  }

  if (ackTime.tv_sec == 0 && ackTime.tv_usec == 0) {
	  // If equals, they're syn or acks
	  if (startSeq != endSeq) {
		  // Check if this is of the last 10 packets
		  multimap<ulong, Range*>::reverse_iterator it, it_end = rm->ranges.rend();
		  int count = 0;
		  for (it = rm->ranges.rbegin(); it != it_end && count < 10; it++) {
			  if (it->second->getStartSeq() == startSeq && it->second->getEndSeq() == endSeq) {
				  if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
					  cerr << "Range with no ACK time. This packet is at the end of the stream, so we presume" \
						  " this is caused by tcpdump being killed before the packets were acked. ";
					  printf("(%lu - %lu - %lu)\n", rm->relative_seq(startSeq), rm->relative_seq(rdbSeq), rm->relative_seq(endSeq));
				  }
				  return 0;
			  }
		  }
		  cerr << "Range with no ACK time. This shouldn't really happen... ";
		  printf("%lu - %lu - %lu\n", rm->relative_seq(startSeq), rm->relative_seq(rdbSeq), rm->relative_seq(endSeq));
	  }
	  return 0;
  }

  /* since ackTime will always be bigger than sendTime,
     (directly comparable timers) timerSub can be used here */
  timersub(&ackTime, &sendTime, &tv);

  if (tv.tv_sec > 0) {
    ms += tv.tv_sec * 1000;
  }
  ms += (int) (tv.tv_usec / 1000);

  if (ms < 0) { /* Should not be possible */
    cerr << "Found byte with 0ms or less latency. Exiting." << endl;
    exit(1);
  }

  if (GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
    cerr << "Latency for range: " << ms << endl;
    if (ms > 1000 || ms < 10) {
      cerr << "Strange latency: " << ms << "ms." << endl;
      cerr << "Start seq: " << rm->relative_seq(startSeq) << " End seq: " << rm->relative_seq(endSeq) << endl;
      cerr << "Size of range: " << endSeq - startSeq << endl;
      cerr << "sendTime.tv_sec: " << sendTime.tv_sec << " - sendTime.tv_usec: "
	   << sendTime.tv_usec << endl;
      cerr << "ackTime.tv_sec : " << ackTime.tv_sec << "  - ackTime.tv_usec : "
	   << ackTime.tv_usec << endl;
      cerr << "Number of retransmissions: " << numRetrans << endl;
      cerr << "Number of bundles: " << numBundled << endl;
    }
  }
  return ms;
}

void Range::setDiff() {
  struct timeval tv;
  long ms = 0;
  /* Use own macro in order to handle negative diffs */
  negtimersub(&recvTime, &sendTime, &tv);

  ms += tv.tv_sec * 1000;
  if(ms >= 0)
    ms += (tv.tv_usec / 1000);
  else
    ms -= (tv.tv_usec / 1000);

  diff = ms;
}

void Range::printValues(){
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
}
