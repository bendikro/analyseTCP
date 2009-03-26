#ifndef RANGEMANAGER_H
#define RANGEMANAGER_H

#include <vector>
#include <iostream>
#include <limits.h>
#include "Range.h"
#include <deque>

/* Forward declarations */
class Range;

struct recvData{
  uint32_t startSeq;
  uint32_t endSeq;
  struct timeval tv;
  vector<struct recvData*>::iterator vit;
};
  
struct sortByStartSeq{
  bool operator()(const struct recvData &x, const struct recvData &y){
    return x.startSeq < y.startSeq;
  }
};

/* Has responsibility for managing ranges, creating,
   inserting and resizing ranges as sent packets and ACKs
   are received */
class RangeManager{
 private:
  uint32_t firstSeq; /* Global start seq */
  uint32_t lastSeq;  /* Global end seq */
  uint32_t lastContinuous; /* Last seq in sequence of ranges without gaps */
  int highestAcked; /* Index of highest acked range */
  struct timeval highestRecvd;
  int  nrRanges;
  long lowestDiff; /* Used to create CDF. */
  long lowestDcDiff; /* Lowest diff when compensated for clock drift */
  float drift; /* Clock drift (ms/s) */
  
  vector<Range*> ranges;
  vector<struct recvData*> recvd;
  //multimap<uint32_t, struct recvData> recvd;
  map<const int, int> cdf;
  map<const int, int> dcCdf;

 public:
  RangeManager(){
    firstSeq = 0;
    lastSeq = 0;
    lastContinuous = 0;
    lowestDiff = LONG_MAX;
    lowestDcDiff = LONG_MAX;
    highestAcked = -1; /* Initialize to -1 to allow incrementation from first range */
    memset(&highestRecvd, 0, sizeof(highestRecvd));
    nrRanges = 0;
    //totNumBytes = 0;
  };
  ~RangeManager();

  /*TODO: Implement verification that all bytes between startSeq of first range
    and endSeq of last range are registered (no holes) */
  void insertSentRange(uint32_t startSeq, uint32_t endSeq, timeval* tv);
  void insertRecvRange(uint32_t startSeq, uint32_t endSeq, timeval* tv);
  void processAck(uint32_t ack, timeval* tv);
  void genStats(struct byteStats* bs);
  Range* getLastRange(){ return ranges.back(); }
  Range* getHighestAcked();
  int getTotNumBytes(){ return lastSeq - firstSeq; }
  int getTimeInterval(Range *r);
  uint32_t getDuration();
  void validateContent();
  void registerRecvDiffs();
  void makeCdf();
  void printCDF();
  void printDcCdf();
  float calcDrift();
  void registerDcDiffs();
  void makeDcCdf();
  int getNumBytes(){ return lastSeq - firstSeq; }
  //bool sortComp(struct recvData&, struct recvData&); 
};

#endif /* RANGEMANAGER_H */
