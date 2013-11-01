#ifndef CONNECTION_H
#define CONNECTION_H

/* Forward declarations */
class RangeManager;
class Range;

#include "RangeManager.h"
#include <math.h>
#include <netinet/in.h>

/* Represents one connection (srcport/dstport pair) */
class Connection {

 public:
  int nrPacketsSent;
  int nrDataPacketsSent;
  int totPacketSize;
  int totBytesSent;
  int totRDBBytesSent;
  int totNewDataSent;
  int totRetransBytesSent;
  int nrRetrans;
  struct in_addr srcIp;
  uint16_t srcPort;
  struct in_addr dstIp;
  uint16_t dstPort;
  int bundleCount;
  ulong firstSeq;
  ulong curSeq;
  // Used for calulcating relative sequence number
  ulong lastLargestEndSeq;      // This is the last largest relative end-seq
  ulong lastLargestSeqAbsolute; // This is the last largest raw seq number
  ulong lastLargestRecvEndSeq;
  ulong lastLargestRecvSeqAbsolute;

  ulong lastLargestAckSeq;
  uint32_t lastLargestAckSeqAbsolute;
  timeval firstSendTime;
  timeval endTime;
  RangeManager *rm;


  Connection(struct in_addr src_ip,
	     uint16_t src_port,
	     struct in_addr dst_ip,
	     uint16_t dst_port,
	     uint32_t seq);

  ~Connection();

  void registerSent(struct sendData* pd);
  Range* registerRange(struct sendData* sd);
  void registerRecvd(struct sendData *sd);
  bool registerAck(ulong ack, timeval* tv);
  void addPacketStats(struct connStats* cs);
  void genBytesLatencyStats(struct byteStats* bs);
  void validateRanges();
  timeval get_duration() ;
  void makeCDF();
  void printCDF(ofstream *stream);
  void printDcCdf(ofstream *stream);
  void makeDcCdf();
  void addRDBStats(int *rdb_sent, int *rdb_miss, int *rdb_hits, int *totBytesSent);
  void genRFiles();
  ulong getNumUniqueBytes();
  string getConnKey();
  string getSrcIp();
 string getDstIp();
 void printPacketDetails();
};
#endif /* CONNECTION_H */
