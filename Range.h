#ifndef RANGE_H
#define RANGE_H

#include <string.h>
#include "analyseTCP.h"
#include "RangeManager.h"

/* Modified timersub macro that has defined behaviour
   also for negative differences */
# define negtimersub(a, b, result)					\
  do {									\
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			\
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			\
    if ( (result)->tv_sec > 0) {					\
      if ((result)->tv_usec < 0) {					\
	--(result)->tv_sec;						\
	(result)->tv_usec += 1000000;					\
      }									\
    } else if ( (result)->tv_sec < 0 ) {				\
      if ((result)->tv_usec > 0) {					\
	++(result)->tv_sec;						\
	(result)->tv_usec = 1000000 - (result)->tv_usec;		\
      } else { /* if (tv_usec < 0) */					\
	(result)->tv_usec *= -1;					\
      }									\
      if((result)->tv_sec == 0 )					\
	(result)->tv_usec *= -1;					\
    }									\
  } while (0)

/* Keeps track of a range of bytes that share send and ack time.
   Trying to make it use as little memory as possible.
*/
class Range {
 private:
  ulong startSeq;
  ulong rdbSeq;
  ulong endSeq;
  struct timeval ackTime;
  struct timeval recvTime;
  struct timeval sendTime;
  long diff, dcDiff;
  RangeManager *rm;
  short payloadLen;
  u_char *data;
  unsigned char numRetrans;
  unsigned char numBundled;

  unsigned int dummy : 1;
  unsigned int acked : 1;
  unsigned int exact_match : 1;

//  int received;

public:
  Range(ulong ss, ulong rdb_orig, ulong es, int data_len, u_char *payload, timeval *tv, bool dmy, RangeManager *rangeManager) {
    startSeq = ss;
    rdbSeq = rdb_orig;
    endSeq = es;
    sendTime = *tv;
    dummy = dmy;
    memset(&ackTime, 0, sizeof(ackTime));
    memset(&ackTime, 0, sizeof(recvTime));
    acked = false;
    numRetrans = 0;
    numBundled = 0;
    diff = 0;
    dcDiff = 0;
    exact_match = 0;
    payloadLen = data_len;
    data = NULL;
    rm = rangeManager;

    if (payloadLen > 0 && payload != NULL) {
	    data = (u_char*) malloc(payloadLen + 1);
	    memcpy(data, payload, payloadLen);
    }

//    printSEQ();
  }

  void insertAckTime(timeval *tv);
  int getDiff(); /* Returns the ACK latency in ms */
  ulong getRDBSeq() { return rdbSeq; }
  ulong getStartSeq() { return startSeq; }
  ulong getEndSeq() { return endSeq; }
  uint32_t getNumRetrans() { return (uint32_t) numRetrans; }
  uint32_t getNumBundled() { return (uint32_t) numBundled; }
  bool isAcked() { return acked; }
  bool isDummy() { return dummy; }
  bool isExactMatched() { return exact_match; }
  void incNumRetrans() { numRetrans++; }
  void incNumBundled() { numBundled++; }
  void setIsAcked() { acked = true; }
  void setExactMatchedAcked() { exact_match = true; }
  void setRDBSeq(ulong rdbs) { rdbSeq = rdbs; }
  void setEndSeq(ulong endseq) { endSeq = endseq; }
  void setStartSeq(ulong ss) { startSeq = ss; }
  void setSendTime(timeval *tv) { sendTime = *tv; }
  void setRecvTime(timeval *tv) { recvTime = *tv; }
  timeval* getSendTime();
  timeval* getRecvTime();
  void setDiff();
  void setDcDiff(long diff) { dcDiff = diff;}
  long getDcDiff() { return dcDiff;}
  long getRecvDiff() { return diff; }
  timeval* getAckTime();
  int getNumBytes() { return (int) payloadLen; }
  void printSEQ();

  /* Debug */
  void printValues();
} __attribute__((packed)); // Remove if your compiler doesn't support packed

#endif /* RANGE_H */
