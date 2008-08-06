#ifndef CONNECTION_H
#define CONNECTION_H

/* Forward declarations */
class RangeManager;

#include "RangeManager.h"

/* Represents one connection (srcport/dstport pair) */
class Connection {

 private:
  int nrPacketsSent;
  int totPacketSize;
  int totBytesSent;
  int nrRetrans;
  uint16_t dstPort;
  uint16_t srcPort;
  int bundleCount;
  int curSize;
  uint32_t endSeq;
  uint32_t firstSeq;
  uint32_t curSeq;
  uint32_t lastLargestSeq;
  timeval firstSendTime;
  RangeManager *rm;

 public:
  Connection(uint16_t src_port, uint16_t dst_port, uint32_t seq);

  ~Connection(){}

  void registerSent(struct sendData* pd);
  void registerRange(struct sendData* sd);
  void registerRecvd(struct sendData *sd);
  void registerAck(uint32_t ack, timeval* tv);
  void genStats(struct connStats* cs);
  void genBLStats(struct byteStats* bs);
  void validateRanges();
  void makeCDF();
  void printCDF();
  void printDcCdf();
  void makeDcCdf();
  int getNumBytes(){ return endSeq - firstSeq; }
};
#endif /* CONNECTION_H */
