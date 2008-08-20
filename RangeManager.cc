#include "RangeManager.h"

/* Register all byes with a common send time as a range */
void RangeManager::insertSentRange(uint32_t startSeq, uint32_t endSeq, timeval* tv){

  if (ranges.size() == 0){ /* First packet in stream */
    if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
      cerr << "-------Creating first range---------" << endl;
    Range* range = new Range(startSeq, endSeq, tv);
    ranges.push_back(range);
    firstSeq = startSeq;
    lastSeq = endSeq;
    return;
  }

  if (startSeq == lastSeq){ /* Next packet in correct sequence */
    if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
      cerr << "-------New range equivalent with packet---------" << endl;
    Range* range = new Range(startSeq, endSeq, tv);
    ranges.push_back(range);
    lastSeq = endSeq;
    return;
  }

  if (startSeq > lastSeq ){ /* Something has gone wrong: missing byte in stream */
    cerr << "RangeManager::insertRange: Missing byte in send range: Exiting." << endl;
    exit(1);
  }

  if (startSeq < lastSeq){ /* We have some kind of overlap */
    if(endSeq <= lastSeq){/* All bytes are already registered: Retransmission */
      if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
	cerr << "-------All bytes have already been registered - discarding---------" << endl;
      /* Traverse all affected ranges and tag all 
	 ranges that contain retransmitted bytes */
      vector<Range*>::reverse_iterator it, it_end;
      it_end = ranges.rend();
      for(it = ranges.rbegin(); it != it_end; it++){
	if (startSeq >= (*it)->getEndSeq())
	  break;
	if ( endSeq > (*it)->getStartSeq())
	  (*it)->incNumRetrans(); /* Count a new retransmssion */
      }
      return;
    }else{ /* Old and new bytes: Bundle */
      if(GlobOpts::debugLevel == 1 || GlobOpts::debugLevel == 5)
	cerr << "-------Overlap: registering some bytes---------" << endl;
      Range* range = new Range(lastSeq, endSeq, tv);
      ranges.push_back(range);
      lastSeq = endSeq;
      /* Traverse all affected ranges and tag all 
	 ranges that contain bundled bytes */
      vector<Range*>::reverse_iterator it, it_end;
      it_end = ranges.rend();
      for(it = ranges.rbegin(); it != it_end; it++){
	if (startSeq >= (*it)->getEndSeq())
	  break;
	if ( endSeq > (*it)->getStartSeq())
	  (*it)->incNumBundled(); /* Count a new bundling */
      }
    } 
  }
}

/* Register all byes with a coomon send time as a range */
void RangeManager::insertRecvRange(uint32_t startSeq, uint32_t endSeq, timeval* tv){
  struct recvData tmpRecv; // = new struct recvData();
  tmpRecv.startSeq = startSeq;
  tmpRecv.endSeq = endSeq;
  tmpRecv.tv = *tv;
  
  if(GlobOpts::debugLevel == 3 || GlobOpts::debugLevel == 5 ){
    cerr << "Inserting receive data: startSeq=" << startSeq << ", endSeq=" << endSeq << endl;
    if(startSeq == 0  || endSeq==0){
      cerr << "Erroneous seq." << endl;
    }
  }
  /* Insert all packets into datastructure */ 
  recvd.push_back(tmpRecv);
  return;
}

/* Register first ack time for all bytes.
   Organize in ranges that have common send and ack times */
void RangeManager::processAck(uint32_t ack, timeval* tv){
  Range* tmpRange;
  int i = highestAcked + 1;

  for( ; i != ranges.size(); i++){
    tmpRange = ranges[i];
    
    if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
      cerr << "tmpRange - startSeq: " << tmpRange->getStartSeq() << " - endSeq: " << tmpRange->getEndSeq() << endl;

    /* All data from this ack has been acked before: return */
    if(ack <= tmpRange->getStartSeq()){
      if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
	cerr << "--------All data has been ACKed before - skipping--------" << endl;
      return;
    }

    /* This ack covers this range, but not more: ack and return */
    if(ack == tmpRange->getEndSeq()){
      if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
	cerr << "--------Ack equivalent with last range --------" << endl;
      tmpRange->insertAckTime(tv);
      highestAcked = i;
      return;
    }

    /* ACK covers more than this range: ACK this range and continue */
    if(ack > tmpRange->getEndSeq()){
      if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
	cerr << "--------Ack covers more than this range: Continue to next --------" << endl;
      tmpRange->insertAckTime(tv);
      highestAcked = i;
      continue;
    }

    /* ACK covers only part of this range: split range and return */
    if(ack > tmpRange->getStartSeq() && ack < tmpRange->getEndSeq()){
      if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
	cerr << "--------Ack covers only parts of this range: Splitting --------" << endl;
      vector<Range*>::iterator it, it_end;
      it_end = ranges.end();
      for(it = ranges.begin(); it != it_end; it++){
	if((*it)->getStartSeq() == tmpRange->getStartSeq() &&
	   (*it)->getEndSeq() == tmpRange->getEndSeq()){
	  /* We have an iterator to tmpRange (is this possible to do without traversing the vector?)*/
	  /* Create new range to insert after modifying existing */
	  Range* newRange = new Range(tmpRange->getStartSeq(), ack, tmpRange->getSendTime());
	  newRange->insertAckTime(tv);

	  /* First part of range: increase startSeq = ack + 1 no ack*/
	  tmpRange->setStartSeq(ack);
	  /* Second part of range: insert before it (tmpRange) */
	  ranges.insert(it, newRange);
	  highestAcked = i;
	  return;
	}
      }
    }

    /* If we get here, something's gone wrong */
    cerr << "tmpRange->startSeq : " << tmpRange->getStartSeq() << endl;
    cerr << "tmpRange->endSeq   : " << tmpRange->getEndSeq() << endl;
    cerr << "ack                : " << ack << endl;
    cerr << "RangeManager::processAck: Error in ack processing. Exiting." << endl;
    exit(1);
  }
}

/* TODO: Check handling of invalid ranges */
void RangeManager::genStats(struct byteStats* bs){
  vector<Range*>::iterator it, it_end;
  int latency;

  it_end = ranges.end();
  for(it = ranges.begin(); it != it_end; it++){
    if ( latency = (*it)->getDiff() ){ /* Skip if invalid */
      bs->cumLat += latency;
      if(latency > bs->maxLat)
	bs->maxLat = latency;
      if(latency < bs->minLat)
	bs->minLat = latency;
    }else{
      continue; /* Skip */
    }
    int retrans = (*it)->getNumRetrans();
    if ( retrans > 0 ){
      if( retrans == 1)
	bs->retrans[0]++;
      if( retrans == 2 ){
	bs->retrans[0]++;
	bs->retrans[1]++;
      }
      if (retrans >= 3 ){
	bs->retrans[0]++;
	bs->retrans[1]++;
	bs->retrans[2]++;
      }
    }
    if (retrans > bs->maxRetrans)
      bs->maxRetrans = retrans;
  }
  bs->nrRanges = ranges.size();
  
}

/* Check that every byte from firstSeq to lastSeq is present.
   Print number of ranges.
   Print number of sent bytes (payload).
   State if send-times occur: how many.
   State if ack-times occur: how many. */
void RangeManager::validateContent(){
  int numAckTimes = 0;
  int numSendTimes = 0;
  uint32_t tmpStartSeq = 0;
  uint32_t tmpEndSeq = 0;

  vector<Range*>::iterator it, it_end;
  it_end = ranges.end();

  /* FirstRange.startSeq == firstSeq
     LastRange.endSeq == lastSeq
     every packet in between are aligned */
  if( ranges.front()->getStartSeq() != firstSeq){
    cerr << "RangeManager::validateContent: firstSeq unaligned: Validation failed. Exiting" << endl;
    exit(1);
  }

  if( ranges.back()->getEndSeq() != lastSeq){
    cerr << "RangeManager::validateContent: lastSeq unaligned: Validation failed. Exiting" << endl;
    exit(1);
  }

  for(it = ranges.begin(); it != it_end; it++){
    if(it == ranges.begin()){
      tmpEndSeq = (*it)->getEndSeq();
      continue;
    }

    if((*it)->getStartSeq() == tmpEndSeq ){
      tmpEndSeq = (*it)->getEndSeq();
    }else{
      cerr << "(*it)->getStartSeq(): " << (*it)->getStartSeq() << endl;
      cerr << "tmpEndSeq           : " << tmpEndSeq << endl;
      cerr << "RangeManager::validateContent: Byte-stream in ranges not continuous. Exiting."
	   << endl;
      exit(1);
    }

    if((*it)->getSendTime())
      numSendTimes++;
    if((*it)->getAckTime())
      numAckTimes++;
  }
  if(nrRanges == 0){
    nrRanges = ranges.size();
  }else{
    if(ranges.size() != nrRanges){
      if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5)
	cerr << "Ranges has been resized. Old size: " << nrRanges
	     << " - New size: " << ranges.size() << endl;
    }
    nrRanges = ranges.size();
  }
  if(GlobOpts::debugLevel == 2 || GlobOpts::debugLevel == 5){
    cerr << "First seq: " << firstSeq << " Last seq: " <<  lastSeq << endl;
    cerr << "Number of ranges: " << ranges.size() << endl;
    cerr << "Number of bytes: " << lastSeq - firstSeq << endl;
    cerr << "numSendTimes: " << numSendTimes << endl;
    cerr << "numAckTimes: " << numAckTimes << endl;
    cerr << "Is first range acked?: " << ranges.front()->isAcked() << endl;
    cerr << "Is last range acked?: " << ranges.back()->isAcked() << endl;
    cerr << "Last range: startSeq: " << ranges.back()->getStartSeq()
	 << " - endSeq: " << ranges.back()->getEndSeq() << endl;
  }
}

/* Reads all packets from receiver dump into a vector */
void RangeManager::registerRecvDiffs(){
    
  vector<Range*>::iterator it, it_end;
  it = ranges.begin();
  it_end = ranges.end();
 
  /* Sort recvd vector */
  // std::stable_sort(recvd.begin(), recvd.end(), sortByStartSeq());

  //vector<vector<struct recvData*>::iterator> deleteList;
  //vector<struct recvData>::iterator recStart = recvd.begin();
  //map<uint32_t, struct recvData>::iterator recStart = recvd.begin();

  for(; it != it_end; it++){
    bool matched = false;
    uint32_t tmpStartSeq = (*it)->getStartSeq();
    uint32_t tmpEndSeq = (*it)->getEndSeq();
    
    if(GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
      cerr << "Processing range: " << tmpStartSeq << " - " << tmpEndSeq << "- Sent:" 
	   << (*it)->getSendTime()->tv_sec << "." << (*it)->getSendTime()->tv_usec << endl;
    }
    
    /* Traverse recv data structs to find 
       lowest time for all corresponding bytes */
    vector<struct recvData>::iterator rit, rit_end;
    //multimap<uint32_t, struct recvData>::iterator rit, rit_end;
    //rit = recStart;
    rit = recvd.begin();
    rit_end = recvd.end();
    for(; rit != rit_end ; rit++){
      //struct recvData tmpRd = (*rit).second;
      struct recvData tmpRd = *rit;
      //uint32_t rss = (*rit).startSeq;
      //uint32_t res = (*rit).endSeq;
      
      //bool doBreak = false;

      /* If the received packet matches the range */
      if( tmpRd.startSeq <= tmpStartSeq && tmpRd.endSeq >= tmpEndSeq ){
	/* Set recvTime only for first match */
	//if(!matched){
	if(timercmp(&(tmpRd.tv), &highestRecvd, >)){
	  highestRecvd = tmpRd.tv;
	  //doBreak = true;
	  //}
	  /* Set recv time to highest value yet to reflect
	     application layer delay upon loss / reordering */
	}
	(*it)->setRecvTime(&highestRecvd);
	matched = true;
	
	if(GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
	  cerr << "Found overlapping recvData: startSeq=" << 
	    tmpRd.startSeq << " - endSeq=" << tmpRd.endSeq << " - Recvd:" 
	       << tmpRd.tv.tv_sec << "." << tmpRd.tv.tv_usec << endl;
	}
	break;
      }
      
      // if(GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
// 	/* Make sure that the RecvRange >= sendRange assertion holds */
// 	if( ( tmpRd.startSeq == tmpStartSeq && tmpRd.endSeq < tmpEndSeq) ||
// 	    ( tmpRd.startSeq > tmpStartSeq && tmpRd.endSeq == tmpEndSeq) ||
// 	    ( tmpRd.startSeq > tmpStartSeq && tmpRd.endSeq <  tmpEndSeq) ){
// 	  cerr << "Found recv data sequence that is smaller than the current range." << endl;
// 	  cerr << "May be caused by erroneous tcp len in dumpfile. Exiting" << endl;
// 	  exit(1);
// 	}
//       }
            
      /* Check for already registered elements and tag them for removal */
      //if ( tmpRd.endSeq < tmpStartSeq ){
	//deleteList.push_back(rit);
	//if (recStart != recvd.begin())
	// recStart = rit-1;
	//recStart = rit;
      //}
      /* A match has been found, break */
      //if(doBreak)
      //	break;
    }
    
    /* Check if match has been found */
    if(!matched){
      cerr << "Found range that has no corresponding received packet. Exiting\n" << endl;
      exit(1);
    }
    
    /* Calculate diff and check for lowest value */
    (*it)->setDiff();
    long diff = (*it)->getRecvDiff();
    if( diff < lowestDiff )
      lowestDiff = diff;

    if(GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
      cerr << "SendTime: " << (*it)->getSendTime()->tv_sec << "." << (*it)->getSendTime()->tv_usec << endl;
      cerr << "RecvTime: " << (*it)->getRecvTime()->tv_sec << "." << (*it)->getRecvTime()->tv_usec << endl;
      cerr << "RecvDiff=" << diff << endl;
      //cerr << "Deletelist size: " << deleteList.size() << endl;
      cerr << "recvd.size()= " << recvd.size() << endl;
    }
    
    /* Delete already registered recvData elements */
//     vector<vector<struct recvData*>::iterator>::reverse_iterator dit, dit_end;
//     dit = deleteList.rbegin();
//     dit_end = deleteList.rend();
//     for(; dit != dit_end; dit++){
//       if(GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
// 	cerr << "Deleting " << (**dit)->startSeq << " - " << (**dit)->endSeq << endl;
//       }
//       free((**dit));
//       recvd.erase(*dit);
//     }
//     deleteList.clear();
  }
  /* End of the current connection. Free recv data */
  //recvd.~multimap();
  recvd.~vector();
}

Range* RangeManager::getHighestAcked(){
  if(highestAcked == -1){ 
    return NULL;
  }else{
    return ranges[highestAcked]; 
  }
}

/* Returns duration of connection (in seconds)*/
uint32_t RangeManager::getDuration(){
  uint32_t time;
  struct timeval startTv, endTv, tv;
  
  endTv =   *((*(ranges.rbegin()))->getSendTime());
  startTv = *((*(ranges.begin()))->getSendTime());
  timersub(&endTv, &startTv, &tv);
  time = tv.tv_sec + (tv.tv_usec / 1000000);
  
  return time;
}

/* Calculate clock drift on CDF */
float RangeManager::calcDrift(){
  /* If connection > 500 ranges &&
     connection.duration > 120 seconds, 
     calculate clock drift */
  
  if (ranges.size() > 500 && getDuration() > 120){
    vector<Range*>::iterator startIt;
    vector<Range*>::reverse_iterator endIt;
    long minDiffStart = LONG_MAX;
    long minDiffEnd = LONG_MAX;
    struct timeval minTimeStart, minTimeEnd, tv;
    int time;
    float tmpDrift;

    startIt = ranges.begin();
    for(int i=0; i < 200; i++){
      if((*startIt)->getRecvDiff() < minDiffStart){
	minDiffStart = (*startIt)->getRecvDiff();
	minTimeStart = *((*startIt)->getSendTime());
      }
      startIt++;
    }
        
    endIt = ranges.rbegin();
    for(int i=0; i < 200; i++){
      if((*endIt)->getRecvDiff() < minDiffEnd){
	minDiffEnd = (*endIt)->getRecvDiff();
	minTimeEnd = *((*endIt)->getSendTime());
      }
      endIt++;
    }
    
    /* Get time interval between values */
    timersub(&minTimeEnd, &minTimeStart, &tv);
    time = tv.tv_sec + (tv.tv_usec / 1000000);
    
    tmpDrift = (float)(minDiffEnd - minDiffStart) / time;

    if (GlobOpts::debugLevel == 4 || GlobOpts::debugLevel == 5){
      cerr << "startMin: " << minDiffStart << endl;
      cerr << "endMin: " << minDiffEnd << endl;
      cerr << "Time: " << time << endl;
      cerr << "Clock drift: " << tmpDrift << " ms/s" << endl;
    }
    drift = tmpDrift;
  }else{
    cerr << "Connection has less than 500 ranges or a duration of less than 2 minutes." << endl;
    cerr << "Drift-compensated CDF will therefore not be calculated." << endl;
    drift = -1;
  }
}
  
/* Returns the difference between the start 
   of the dump and r in seconds */
int RangeManager::getTimeInterval(Range *r){
  struct timeval start, current, tv;
  int time;
  
  start = *((*(ranges.begin()))->getSendTime());
  current = *(r->getSendTime());
  timersub(&current, &start, &tv);
  time = tv.tv_sec + (tv.tv_usec / 1000000);
  
  return time;
}

void RangeManager::makeCdf(){
  long diff;
  vector<Range*>::iterator it, it_end;
  it = ranges.begin();
  it_end = ranges.end();
  
  for(; it != it_end; it++){
    diff = (*it)->getRecvDiff();
    diff -= lowestDiff;

    if ( cdf.count(diff) > 0 ){
      /*  Add bytes to bucket */
      map<const int, int>::iterator element = cdf.find(diff);
      element->second = element->second + (*it)->getNumBytes();
    }else{
      /* Initiate new bucket */
      cdf.insert(pair<int, int>(diff, (*it)->getNumBytes()));
    }  
  }
}

void RangeManager::registerDcDiffs(){
  vector<Range*>::iterator it, it_end;
  it = ranges.begin();
  it_end = ranges.end();
  
  for(; it != it_end; it++){
    long diff = (*it)->getRecvDiff();
    /* Compensate for drift */
    diff -= (int)(drift * getTimeInterval(*it));
    
    (*it)->setDcDiff(diff);
    
    if( diff < lowestDcDiff )
      lowestDcDiff = diff;
    
    if(GlobOpts::debugLevel==4 || GlobOpts::debugLevel==5){
      cerr << "dcDiff: " << diff << endl;
    }
  }
}

void RangeManager::makeDcCdf(){
  vector<Range*>::iterator it, it_end;
  it = ranges.begin();
  it_end = ranges.end();
  
  for(; it != it_end; it++){
    long diff = (*it)->getDcDiff() - lowestDcDiff;
    if ( dcCdf.count(diff) > 0 ){
      /*  Add bytes to bucket */
      map<const int, int>::iterator element = dcCdf.find(diff);
      element->second = element->second + (*it)->getNumBytes();
    }else{
      /* Initiate new bucket */
      dcCdf.insert(pair<int, int>(diff, (*it)->getNumBytes()));
    }
    if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
      (*it)->printValues();
    }
  }
}

void RangeManager::printCDF(){
  map<const int, int>::iterator nit, nit_end;
  float cdfSum = 0;
  nit = cdf.begin();
  nit_end = cdf.end();

  if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
    cerr << "lowestDiff: " << lowestDiff << endl;
  }

  cout << "#Relative delay      Percentage" << endl;
  for(; nit != nit_end; nit++){
    cdfSum += (float)(*nit).second / getTotNumBytes();
    printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
  }
}

void RangeManager::printDcCdf(){
  map<const int, int>::iterator nit, nit_end;
  float cdfSum = 0;
  nit = dcCdf.begin();
  nit_end = dcCdf.end();

  if(GlobOpts::debugLevel== 4 || GlobOpts::debugLevel== 5){
    cerr << "lowestDcDiff: " << lowestDcDiff << endl;
  }

  /* Do not print cdf for short conns */
  if(drift == -1)
    return;
  
  cout << "#------ Drift : " << drift << "ms/s ------" << endl;
  cout << "#Relative delay      Percentage" << endl;
  for(; nit != nit_end; nit++){
    cdfSum += (float)(*nit).second / getTotNumBytes();
    printf("time: %10d    CDF: %.10f\n",(*nit).first, cdfSum);
  }
}
