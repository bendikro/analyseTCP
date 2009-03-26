#include "Dump.h"

/* Methods for class Dump */
Dump::Dump( string src_ip, string dst_ip, int dst_port, string fn ){
  srcIp = src_ip;
  dstIp = dst_ip;
  dstPort = dst_port;
  filename = fn;
  sentPacketCount = 0;
  sentBytesCount = 0;
  recvPacketCount = 0;
  recvBytesCount = 0;
  ackCount = 0;
}

/* Traverse the pcap dump and call methods for processing the packets 
   This generates initial one-pass statistics from sender-side dump. */
void Dump::analyseSender (){
  int packetCount = 0;
  string tmpDstIp = dstIp;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr h;
  const u_char *data;
  map<uint16_t, Connection*>::iterator it, it_end;
  
  pcap_t *fd = pcap_open_offline(filename.c_str(), errbuf);
  if ( fd == NULL ) {
    cerr << "pcap: Could not open file" << filename << endl;
    exit(1);
  }
  
  /* Handle NAT between sender and receiver */

  /* TODO: Seperate NAT-handling options for 
     NAT on sender side and receiver side */  
  if(!GlobOpts::natIP.empty()){
    cerr << "NATing handled" << endl;
    tmpDstIp = GlobOpts::natIP;
    cerr << "dstIp: " << dstIp << endl;
  }
  
  /* Set up pcap filter to include only outgoing tcp
     packets with correct ip and port numbers.
     We exclude packets with no TCP payload. */
  struct bpf_program compFilter;
  stringstream filterExp;
  filterExp << "tcp && src host " << srcIp << " && dst host "
	    << tmpDstIp << " && dst port " << dstPort
	    << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";
  
  /* Filter to get outgoing packets */
  if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
    cerr << "Couldn't parse filter " << filterExp << "Error:" << pcap_geterr(fd) << endl;
    exit(1);
  }
  
  if (pcap_setfilter(fd, &compFilter) == -1) {
    cerr << "Couldn't install filter: " << filterExp << "Error: " << pcap_geterr(fd) << endl;
    exit(1);
  }
  
  /* Sniff each sent packet in pcap tracefile: */
  do {
    data = (const u_char *)pcap_next(fd, &h);
    if(data == NULL){
      char errMsg[] = "\nNo more data on file\n";
      pcap_perror(fd, errMsg);
    }else{
      processSent(&h, data); /* Sniff packet */
      packetCount++;
    }
  } while(data != NULL);
  
  pcap_close(fd);
  
  if(GlobOpts::bwlatency){
    /* DEBUG: Validate range */
    if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
      cerr << "---------------Begin first validation--------------" << endl;
    it_end = conns.end();
    for(it = conns.begin(); it != it_end; it++){
      it->second->validateRanges();
    }
    if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
      cerr << "---------------End of first validation--------------" << endl;
  }
  
  /* For byte-latency: process received packets
     and enter timestamps for acks */
  if ( GlobOpts::bwlatency ){
    pcap_t *fd2 = pcap_open_offline(filename.c_str(), errbuf);
    if ( fd2 == NULL ) {
      cerr << "pcap: Could not open file" << filename << endl;
      exit(1);
    }
    
    /* Set up pcap filter to get only incoming tcp packets
       with correct IP and ports and the ack flag set */
    filterExp.str("");
    filterExp << "tcp && src host " << tmpDstIp << " && dst host "
	      << srcIp << " && src port " << dstPort
	      << " && ((tcp[tcpflags] & tcp-syn) != tcp-syn)"
	      << " && ((tcp[tcpflags] & tcp-fin) != tcp-fin)"
	      << " && ((tcp[tcpflags] & tcp-ack) == tcp-ack)";
    if (pcap_compile(fd2, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
      cerr << "Couldn't parse filter " << filterExp << "Error:" << pcap_geterr(fd2) << endl;
      exit(1);
    }
    
    if (pcap_setfilter(fd2, &compFilter) == -1) {
      cerr << "Couldn't install filter: " << filterExp << "Error: " << pcap_geterr(fd2) << endl;
      exit(1);
    }
    
    /* Sniff each sent packet in pcap tracefile: */
    do {
      data = (const u_char *)pcap_next(fd2, &h);
      if(data == NULL){
	char errMsg[] = "\nNo more data on file\n";
	pcap_perror(fd2, errMsg);
      }else{
	processAcks(&h, data); /* Sniff packet */
	packetCount++;
      }
    } while(data != NULL);
    
    pcap_close(fd2);
  }
  
  if ( GlobOpts::bwlatency ){
    /* DEBUG: Validate ranges */
    if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
      cerr << "---------------Begin second validation--------------" << endl;
    it_end = conns.end();
    for(it = conns.begin(); it != it_end; it++){
      it->second->validateRanges();
    }
    if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5 )
      cerr << "---------------End of second validation--------------" << endl;
  }
  
  /* Initiate struct for aggregate stats */
  struct connStats cs;
  memset(&cs, 0, sizeof(cs));
  
  int aggrMaxLat = 0;
  int aggrMinLat = (numeric_limits<int>::max)();
  float aggrCumLat = 0;
  int aggrConns = 0;
  int r1=0, r2=0, r3=0;
  int maxRetrans = 0;
  
  //for (int i = 0; i<=sizeof(retrans); i++)
  // retrans[i] = 0;
  
  map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->genStats(&cs);
    
    /* Generate bytewise latency statistics */
    if(GlobOpts::bwlatency){
      /* Initialize bs struct */
      struct byteStats bs;
      memset(&bs, 0, sizeof(bs));
      bs.minLat = (numeric_limits<int>::max)();
      cIt->second->genBLStats(&bs);
      
      if(GlobOpts::aggregate){
	if(bs.minLat < aggrMinLat)
	  aggrMinLat = bs.minLat;
	if(bs.maxLat > aggrMaxLat)
	  aggrMaxLat = bs.maxLat;
	aggrCumLat += bs.avgLat;
	
	r1 += bs.retrans[0];
	r2 += bs.retrans[1];
	r3 += bs.retrans[2];
	if( maxRetrans < bs.maxRetrans ){
	  maxRetrans = bs.maxRetrans;
	}
	
	if(GlobOpts::verbose){
	  if(cs.nrPacketsSent){ /* To avoid division by 0 */
	    /* Print aggregated statistics */
	    cout << "--------------------------------------------------" <<endl;
	    cout << "Aggregate Statistics      : " << conns.size() << " connections:" << endl;
	    cout << "Total bytes sent          : " << sentBytesCount << endl;
	    cout << "Total packets sent        : " << cs.nrPacketsSent << endl;
	    cout << "Average payload size      : " << (sentBytesCount / cs.nrPacketsSent) << endl;
	    cout << "Number of retransmissions : " << cs.nrRetrans << endl;
	    cout << "Bundled segment packets   : " << cs.bundleCount << endl;
	    cout << "Estimated loss rate       : " << (((float)cs.nrRetrans / cs.nrPacketsSent) * 100) 
		 << "%" << endl;
	    if(GlobOpts::bwlatency){
	      cout << "--------------------------------------------------" <<endl;
	      /* Print Aggregate bytewise latency */
	      cout << "Bytewise latency" << endl;
	      cout << "Minimum latency : " << aggrMinLat << endl;
	      cout << "Maximum latency : " << aggrMaxLat << endl;
	      cout << "Average latency : " << aggrCumLat / conns.size() << endl;
	      cout << "--------------------------------------------------" << endl;
	      cout << "Occurrences of 1. retransmission : " << r1 << endl;
	      cout << "Occurrences of 2. retransmission : " << r2 << endl; 
	      cout << "Occurrences of 3. retransmission : " << r3 << endl;
	      cout << "Max retransmissions              : " << maxRetrans << endl;
	    }
	  }
	}else{
	  cout << cs.nrPacketsSent << " " << cs.nrRetrans
	       << " " << cs.bundleCount << " " << (((float)cs.nrRetrans / cs.nrPacketsSent) * 100) 
	       << endl;
	}
      }
    }
  }
}
  
/* Process outgoing packets */
void Dump::processSent(const struct pcap_pkthdr* header, const u_char *data){
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const char *payload; /* Packet payload */
  const struct timeval *hdrTv; /* Pcap timestamp */
  Connection *tmpConn;

  /* Finds the different headers+payload */
  ethernet = (struct sniff_ethernet*)(data);
  ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
  u_int ipSize = ntohs(ip->ip_len);
  u_int ipHdrLen = IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + ipHdrLen);
  u_int tcpHdrLen = TH_OFF(tcp)*4;

  /* Check if connection exists. If not, create a new */
  if (conns.count(ntohs(tcp->th_sport)) == 0){
    tmpConn = new Connection(ntohs(tcp->th_sport),
			     ntohs(tcp->th_dport), ntohl(tcp->th_seq));
    conns.insert(pair<uint16_t, Connection*>(ntohs(tcp->th_sport), tmpConn));
  }else{
    tmpConn = conns[ntohs(tcp->th_sport)];
  }

  /* Prepare packet data struct */
  struct sendData sd;
  sd.totalSize   = header->len;
  sd.ipSize      = ipSize;
  sd.ipHdrLen    = ipHdrLen;
  sd.tcpHdrLen   = tcpHdrLen;
  sd.payloadSize = ipSize - (ipHdrLen + tcpHdrLen);
  sd.seq         = ntohl(tcp->th_seq);
  sd.endSeq      = sd.seq + sd.payloadSize;
  sd.time        = header->ts;

  sentPacketCount++;
  sentBytesCount += sd.payloadSize;
  tmpConn->registerSent(&sd);

  if(GlobOpts::bwlatency)
    tmpConn->registerRange(&sd);
}

/* Process incoming ACKs */
void Dump::processAcks(const struct pcap_pkthdr* header, const u_char *data){
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  timeval hdrTv = header->ts;

  ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
  u_int ipHdrLen = IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + ipHdrLen);

  /* It should not be possible that the connection is not yet created */
  if (conns.count(ntohs(tcp->th_dport)) == 0){
    cerr << "Ack for unregistered connection found. Conn: "
	 << ntohs(tcp->th_dport) << " - Ignoring." << endl;
    return;
  }
  ackCount++;
  conns[ntohs(tcp->th_dport)]->registerAck(ntohl(tcp->th_ack), &hdrTv);
}

/* Analyse receiver dump - create CDFs */ 
void Dump::processRecvd(string recvFn){
  int packetCount = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr h;
  const u_char *data;
  map<uint16_t, Connection*>::iterator it, it_end;

  pcap_t *fd = pcap_open_offline(recvFn.c_str(), errbuf);
  if ( fd == NULL ) {
    cerr << "pcap: Could not open file" << recvFn << endl;
    exit(1);
  }

  /* Set up pcap filter to include only incoming tcp
     packets with correct IP and port numbers.
     We exclude packets with no TCP payload. */
  struct bpf_program compFilter;
  stringstream filterExp;
  filterExp << "tcp && src host " << srcIp << " && dst host "
	    << dstIp << " && dst port " << dstPort
	    << " && (ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) >= 1";
  /* Filter to get outgoing packets */
  if (pcap_compile(fd, &compFilter, (char*)((filterExp.str()).c_str()), 0, 0) == -1) {
    cerr << "Couldn't parse filter " << filterExp << "Error:" << pcap_geterr(fd) << endl;
    exit(1);
  }

  if (pcap_setfilter(fd, &compFilter) == -1) {
    cerr << "Couldn't install filter: " << filterExp << "Error: " << pcap_geterr(fd) << endl;
    exit(1);
  }

  /* Sniff each sent packet in pcap tracefile: */
  do {
    data = (const u_char *)pcap_next(fd, &h);
    if(data == NULL){
      char errMsg[] = "\nNo more data on file\n";
      pcap_perror(fd, errMsg);
    }else{
      processRecvd(&h, data); /* Sniff packet */
      packetCount++;
    }
  } while(data != NULL);

  pcap_close(fd);
  
  /* Traverse ranges in senderDump and compare to
     corresponding bytes / ranges in receiver ranges
     place timestamp diffs in buckets */
  makeCDF();

  printCDF();

  /* Calculate clock drift for all eligible connections
     eligible: more than 500 ranges && 
     more than 2 minutes duration 
  make drift compensated CDF*/
  makeDcCdf();

  printDcCdf();
}

/* Process outgoing packets */
void Dump::processRecvd(const struct pcap_pkthdr* header, const u_char *data){
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const char *payload; /* Packet payload */
  const struct timeval *hdrTv; /* Pcap timestamp */
  Connection *tmpConn;

  /* Finds the different headers+payload */
  ethernet = (struct sniff_ethernet*)(data);
  ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
  u_int ipSize = ntohs(ip->ip_len);
  u_int ipHdrLen = IP_HL(ip)*4;
  tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + ipHdrLen);
  u_int tcpHdrLen = TH_OFF(tcp)*4;

  /* Check if connection exists. If not, exit with exception*/
  if (conns.count(ntohs(tcp->th_sport)) == 0){
    cerr << "Connection found in recveiver dump that does not exist in sender. Maybe NAT is in effect?  Exiting." << endl;
    exit(1);
  }else{
    tmpConn = conns[ntohs(tcp->th_sport)];
  }
    
  /* Prepare packet data struct */
  struct sendData sd;
  sd.totalSize   = header->len;
  sd.ipSize      = ipSize;
  sd.ipHdrLen    = ipHdrLen;
  sd.tcpHdrLen   = tcpHdrLen;
  sd.payloadSize = ipSize - (ipHdrLen + tcpHdrLen);
  sd.seq         = ntohl(tcp->th_seq);
  sd.endSeq      = sd.seq + sd.payloadSize;
  sd.time        = header->ts;

  recvPacketCount++;
  recvBytesCount += sd.payloadSize;
  
  tmpConn->registerRecvd(&sd);
}

void Dump::makeCDF(){
  map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->makeCDF();
  }
}

void Dump::printCDF(){
  map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->printCDF();
  }
}

void Dump::printDcCdf(){
  map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->printDcCdf();
  }
}

void Dump::makeDcCdf(){
  map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->makeDcCdf();
  }
}

void Dump::printDumpStats(){
  cout << endl << endl;
  cout << "General info:" << endl;
  cout << "srcIp: " << srcIp << endl;;
  cout << "dstIp: " << dstIp << endl;
  cout << "dstPort: " << dstPort << endl;
  cout << "filename: " << filename << endl;
  cout << "sentPacketCount: " << sentPacketCount << endl;
  cout << "sentBytesCount: " << sentBytesCount << endl;
  cout << "ackCount: " << ackCount << endl;
  if(GlobOpts::withRecv){
    cout << "recvPacketCount:" << recvPacketCount << endl;
    cout << "recvBytesCount: " << recvBytesCount << endl;
    cout << "packetLoss: " << ((float)(sentPacketCount - recvPacketCount) / sentPacketCount) * 100 <<  "\%" << endl; 
  }
}

void Dump::genRFiles(){
 map<uint16_t, Connection*>::iterator cIt, cItEnd;
  for(cIt = conns.begin(); cIt != conns.end(); cIt++){
    cIt->second->genRFiles();
  }
}
