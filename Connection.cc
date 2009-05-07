#include "Connection.h"

/* Methods for class Connection */
Connection::Connection(uint16_t src_port, uint16_t dst_port, uint32_t seq){
  nrPacketsSent  = 0;
  totPacketSize  = 0;
  totBytesSent   = 0;
  nrRetrans      = 0;
  srcPort        = src_port;
  dstPort        = dst_port;
  lastLargestSeq = 0;
  firstSeq       = seq;
  curSeq         = 0;
  bundleCount    = 0;
  memset(&firstSendTime, 0, sizeof(firstSendTime));
  memset(&endTime, 0, sizeof(endTime));

  rm = new RangeManager();
}

/* Count bundled and retransmitted packets from sent data */
void Connection::registerSent(struct sendData* sd){
  totPacketSize += sd->totalSize;
  nrPacketsSent++;
  
  if( sd->endSeq > lastLargestSeq){ /* New data */
    lastLargestSeq = sd->endSeq;
    if( (sd->seq == curSeq) && (sd->endSeq > endSeq)){
      bundleCount++;
    } else if( (sd->seq > curSeq) && (sd->seq < endSeq) && (sd->endSeq > endSeq)){
      bundleCount++;
    }
  } else if(curSeq > 0 && sd->seq <= curSeq){ /* All seen before */
    nrRetrans++;
  } 
  
  if( ( (sd->seq >= curSeq) && sd->payloadSize > 0) ||
      ( (sd->seq < firstSeq) && sd->payloadSize > 0)) /* Wrapped seq nr. */
    {
      curSeq = sd->seq;
      curSize = sd->payloadSize;
      endSeq = sd->endSeq;
    }
  totBytesSent += sd->payloadSize; 
}

/* Process range for outgoing packet */
void Connection::registerRange(struct sendData* sd){
  if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5){
    timeval offset;
    if( firstSendTime.tv_sec == 0 && firstSendTime.tv_usec == 0){
      firstSendTime = sd->time;
    }
    timersub(&(sd->time), &firstSendTime, &offset);

    cerr << "Registering new outgoing. Conn: " << srcPort << " Seq: " << sd->seq << endl;
    cerr << "Time offset: Secs: " << offset.tv_sec << " uSecs: " << offset.tv_usec << endl;
    cerr << "Payload: " << sd->payloadSize << endl;
  }

  rm->insertSentRange(sd->seq, sd->endSeq, &(sd->time));
  if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5){
    cerr << "Last range: startSeq: " << rm->getLastRange()->getStartSeq() << " - endSeq: " << rm->getLastRange()->getEndSeq() << " - size: " << rm->getLastRange()->getEndSeq() - rm->getLastRange()->getStartSeq() << endl;
    cerr << endl;
  }
}

/* Register times for first ACK of each byte */
void Connection::registerAck(uint32_t ack, timeval* tv){
  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
    timeval offset;
    timersub(tv, &firstSendTime, &offset);
    
    cerr << endl << "Registering new ACK. Conn: " << srcPort << " Ack: " << ack << endl;
    cerr << "Time offset: Secs: " << offset.tv_sec << " uSecs: " << offset.tv_sec << endl;
  }

  rm->processAck(ack, tv);
  
  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5) {
    if(rm->getHighestAcked()!=NULL){
      cerr << "highestAcked: startSeq: " << rm->getHighestAcked()->getStartSeq() << " - endSeq: " 
	   << rm->getHighestAcked()->getEndSeq() << " - size: " 
	   << rm->getHighestAcked()->getEndSeq() - rm->getHighestAcked()->getStartSeq() << endl;
    }
  }
}

/* Generate statistics for each connection.
   update aggregate stats if requested */
void Connection::genStats(struct connStats* cs){
  if(!(GlobOpts::aggOnly)){
    cout << "Src_port: " << srcPort << " Dst_port: " << dstPort << endl;
    cout << "Duration: " << rm->getDuration() << " seconds ( " 
	 << ((float)rm->getDuration() / 60 / 60) << " hours )" << endl;
    cout << "Total packets sent: " << nrPacketsSent << endl;
    cout << "Total bytes sent (payload): " << totBytesSent << endl;
    cout << "Average payload size: " << (float)(totBytesSent / nrPacketsSent) << endl;
    cout << "Number of retransmissions: " << nrRetrans << endl;
    cout << "Number of packets with bundled segments: " << bundleCount << endl;
    cout << "Estimated loss rate: " << (((float)nrRetrans / nrPacketsSent) * 100) << "%" << endl;
    cout << "Number of unique bytes: " << getNumBytes() << endl;
    cout << "Redundancy: " << ((float)(totBytesSent - (getNumBytes())) / totBytesSent) * 100 << "\%" << endl;
    cout << "--------------------------------------------------" << endl;
  }
  
  if(GlobOpts::aggregate){
    cs->totPacketSize += totPacketSize;
    cs->nrPacketsSent += nrPacketsSent;
    cs->nrRetrans += nrRetrans;
    cs->bundleCount += bundleCount;
    cs->totUniqueBytes += getNumBytes();
  }
}

/* Generate statistics for bytewise latency */
 void Connection::genBLStats(struct byteStats* bs){
   /* Iterate through vector and gather data */
   rm->genStats(bs);
   bs->avgLat = (float)bs->cumLat / bs->nrRanges;
   
   if(!(GlobOpts::aggOnly)){
     cout << "Bytewise latency - Conn: " <<  srcPort << endl;
     cout << "Maximum latency  : " << bs->maxLat << "ms" << endl;
     cout << "Minimum latency  : " << bs->minLat << "ms" << endl;
     cout << "Average latency  : " << bs->avgLat << "ms" << endl;
     cout << "--------------------------------------------------" << endl;
     cout << "Occurrences of 1. retransmission : " << bs->retrans[0] << endl;
     cout << "Occurrences of 2. retransmission : " << bs->retrans[1] << endl; 
     cout << "Occurrences of 3. retransmission : " << bs->retrans[2] << endl;
     cout << "Max retransmissions              : " << bs->maxRetrans << endl;
     cout << "==================================================" << endl << endl;
   }
 }

/* Check validity of connection range and time data */
void Connection::validateRanges(){
  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
    cerr << "###### Validation of range data ######" << endl;
    cerr << "Connection - srcPort: " << srcPort << endl;
  }
  rm->validateContent();
  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
    cerr << "Validation successful." << endl;
    cerr << "###### End of validation ######" << endl;
  }
}

void Connection::registerRecvd(struct sendData *sd){
  /* Insert range into datastructure */
  rm->insertRecvRange(sd->seq, sd->endSeq, &(sd->time));
}

void Connection::makeCDF(){
  rm->registerRecvDiffs();
  rm->makeCdf();
}

void Connection::printCDF(){
  cout << endl << endl << endl;
  cout << "#------CDF - Conn: " << srcPort << " --------" << endl; 
  rm->printCDF();
}

void Connection::printDcCdf(){
  cout << endl << endl << endl;
  cout << "#------Drift-compensated CDF - Conn: " << srcPort << " --------" << endl; 
  rm->printDcCdf();
}

void Connection::makeDcCdf(){
  if ( rm->calcDrift() == 0 ){
    rm->registerDcDiffs();
    rm->makeDcCdf();
  }
}

void Connection::genRFiles(){
  rm->genRFiles(srcPort);
}

int Connection::getNumBytes(){ 
  if ( endSeq > firstSeq )
    return endSeq - firstSeq;
  else {
    return (UINT_MAX - firstSeq) + endSeq; 
  }
}
