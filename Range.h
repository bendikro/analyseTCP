#ifndef RANGE_H
#define RANGE_H

#include <string.h>
#include "analyseTCP.h"

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

/* Keeps track of a range of bytes that share send and ack time */
class Range{
 private:
  bool dummy;
  uint32_t startSeq;
  uint32_t endSeq;
  struct timeval sendTime;
  struct timeval ackTime;
  struct timeval recvTime;
  bool acked;
  int numRetrans;
  int numBundled;
  long diff, dcDiff;

 public:
  Range(uint32_t ss, uint32_t es, timeval* tv, bool dmy){
    startSeq = ss;
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
  }

  ~Range();

  void insertAckTime(timeval*tv);
  int getDiff(); /* Returns the ACK latency in ms */
  uint32_t getStartSeq(){ return startSeq; }
  uint32_t getEndSeq(){ return endSeq; }
  uint32_t getNumRetrans(){ return numRetrans; }
  uint32_t getNumBundled(){ return numBundled; }
  bool isAcked(){ return acked; }
  bool isDummy(){ return dummy; }
  void incNumRetrans(){ numRetrans++; }
  void incNumBundled(){ numBundled++; }
  void setIsAcked(){acked = true; }
  void setStartSeq(uint32_t ss){ startSeq = ss; }
  void setSendTime(timeval *tv){ sendTime = *tv; }
  void setRecvTime(timeval *tv){ recvTime = *tv; }
  timeval* getSendTime();
  timeval* getRecvTime();
  void setDiff();
  void setDcDiff(long diff){ dcDiff = diff;}
  long getDcDiff(){ return dcDiff;}
  long getRecvDiff(){ return diff; }
  timeval* getAckTime();
  int getNumBytes(); /* Return number of bytes in range */

  /* Debug */
  void printValues();
};

#endif /* RANGE_H */
