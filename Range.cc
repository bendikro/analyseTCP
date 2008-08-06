#include "Range.h"

/* Range */
void Range::insertAckTime(timeval *tv){
  ackTime = *tv;
  acked = true;
}

timeval* Range::getSendTime(){
  if(sendTime.tv_sec == 0 && sendTime.tv_usec == 0)
    return NULL;
  else
    return &sendTime;
}

timeval* Range::getAckTime(){
  if(ackTime.tv_sec == 0 && ackTime.tv_usec == 0)
    return NULL;
  else
    return &ackTime;
}

timeval* Range::getRecvTime(){
  if(recvTime.tv_sec == 0 && recvTime.tv_usec == 0)
    return NULL;
  else
    return &recvTime;
}

/* Get the difference between send and ack time for this range */
int Range::getDiff(){
  struct timeval tv;
  int ms = 0;

  if (sendTime.tv_sec == 0 && sendTime.tv_usec == 0){
    cerr << "Range without a send time. Skipping." << endl;
    //removeConnection(); /* Connection has gone bad: Remove it */
    return 0;
  }

  if(ackTime.tv_sec == 0 && ackTime.tv_usec == 0){
    cerr << "Range with no ACK time. Skipping." << endl;
    //removeConnection(); /* Connection has gone bad: Remove it */
    return 0;
  }

  /* since ackTime will always be bigger than sendTime,
     (directly comparable timers) timerSub can be used here */
  timersub(&ackTime, &sendTime, &tv);

  if (tv.tv_sec > 0){
    ms += tv.tv_sec * 1000;
  }
  ms += (tv.tv_usec / 1000);

  if(ms < 0){ /* Should not be possible */
    cerr << "Found byte with 0ms or less latency. Exiting." << endl;
    exit(1);
  }

  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
    cerr << "Latency for range: " << ms << endl;
    if (ms > 1000 || ms < 10){
      cerr << "Strange latency: " << ms << "ms." << endl;
      cerr << "Start seq: " << startSeq << " End seq: " << endSeq << endl;
      cerr << "Size of range: " << endSeq - startSeq << endl;
      cerr << "sendTime.tv_sec: " << sendTime.tv_sec << " - sendTime.tv_usec: " << sendTime.tv_usec << endl;
      cerr << "ackTime.tv_sec : " << ackTime.tv_sec << "  - ackTime.tv_usec : " << ackTime.tv_usec << endl;
      cerr << "Number of retransmissions: " << numRetrans << endl;
      cerr << "Number of bundlings: " << numBundled << endl;
    }
  }

  return ms;
}

void Range::setDiff(){
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

int Range::getNumBytes(){
  return endSeq - startSeq;
}

void Range::printValues(){
  cerr << endl << "-------RangePrint-------" << endl;
  cerr << "startSeq   : " << startSeq << endl;
  cerr << "endSeq     : " << endSeq << endl;
  cerr << "sendTime   : " << sendTime.tv_sec << "." << sendTime.tv_usec << endl;
  cerr << "ackTime    : " << ackTime.tv_sec << "." << ackTime.tv_usec << endl;
  cerr << "recvTime   : " << recvTime.tv_sec << "." << recvTime.tv_usec << endl;
  cerr << "acked      : " << acked << endl;
  cerr << "numRetrans : " << numRetrans << endl;;
  cerr << "numBundled : " << numBundled << endl;
  cerr << "diff       : " << diff << endl;
  cerr << "dcDiff     : " << dcDiff << endl << endl;;
}
