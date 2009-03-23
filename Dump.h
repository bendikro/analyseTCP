#ifndef DUMP_H
#define DUMP_H

#include <string>
#include <map>
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <limits>
#include <arpa/inet.h>

#include "Connection.h"

/* Forward declarations */
class Connection;

/* Represents one dump, and keeps globally relevant information */
class Dump {

 private:
  string srcIp;
  string dstIp;
  string filename;
  int dstPort;
  int sentPacketCount;
  int sentBytesCount;
  int recvPacketCount;
  int recvBytesCount;
  int ackCount;
  map<uint16_t, Connection*> conns;

  void processSent(const struct pcap_pkthdr* header, const u_char *data);
  void processRecvd(const struct pcap_pkthdr* header, const u_char *data);
  void processAcks(const struct pcap_pkthdr* header, const u_char *data);
  void registerRecvd(const struct pcap_pkthdr* header, const u_char *data);
  void makeCDF();
  void printCDF();
  void printDcCdf();
  void makeDcCdf();
 public:
  Dump( string src_ip, string dst_ip, int dst_port, string fn );
  ~Dump ();

  void analyseSender();
  void processRecvd(string fn);
  void printDumpStats();
};

#endif /* DUMP_H */
