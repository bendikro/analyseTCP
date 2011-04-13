/*************************************************************************************
**************************************************************************************
**                                                                                  **
**  analyseTCP - Tool for analysing sender side tcpdump                             **
**               files with regard to latency.                                      **
**                                                                                  **
**  Copyright (C) 2007     Andreas Petlund  - andreas@petlund.no                    **
**                     and Kristian Evensen - kristrev@ifi.uio.no                   **
**                                                                                  **
**     This program is free software; you can redistribute it and/or modify         **
**     it under the terms of the GNU General Public License as published by         **
**     the Free Software Foundation; either version 2 of the License, or            **
**     (at your option) any later version.                                          **
**                                                                                  **
**     This program is distributed in the hope that it will be useful,              **
**     but WITHOUT ANY WARRANTY; without even the implied warranty of               **
**     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                **
**     GNU General Public License for more details.                                 ** 
**                                                                                  **
**     You should have received a copy of the GNU General Public License along      **
**     with this program; if not, write to the Free Software Foundation, Inc.,      **
**     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.                  **
**                                                                                  **
**************************************************************************************
*************************************************************************************/

#include "analyseTCP.h"

/* Initialize global options */
bool GlobOpts::aggregate      = false;
bool GlobOpts::aggOnly        = false;
bool GlobOpts::withRecv       = false;
bool GlobOpts::transport      = false;
bool GlobOpts::genRFiles      = false;
string GlobOpts::prefix       = "";
int GlobOpts::debugLevel      = 0;
bool GlobOpts::incTrace        = false;
string GlobOpts::sendNatIP    = "";
string GlobOpts::recvNatIP    = "";


void usage (char* argv){
  printf("Usage: %s [-s|r|p|f|g|t|u|m|n|a|A|d]\n", argv);
  printf("Required options:\n");
  printf(" -s <sender ip>     : Sender ip.\n");
  printf(" -f <pcap-file>     : Sender-side dumpfile.\n");
  printf("Other options:\n");
  printf(" -r <receiver ip>   : Receiver ip. If not given, analyse all receiver IPs\n");
  printf(" -q <sender port>   : Sender port. If not given, analyse all sender ports\n");
  printf(" -p <receiver port> : Receiver port. If not given, analyse all receiver ports\n");
  printf(" -g <pcap-file>     : Receiver-side dumpfile\n");
  printf(" -t                 : Calculate transport-layer delays\n");
  printf("                    : (if not set, application-layer delay is calculated)\n");
  printf(" -u <prefix>        : Write statistics to comma-separated files (for use with R)\n");
  printf("                      <prefix> assigns an output filename prefix.\n");
  printf(" -m <IP>            : Sender side external NAT address (as seen on recv dump)\n");
  printf(" -n <IP>            : Receiver side local address (as seen on recv dump)\n");
  printf(" -a                 : Produce aggregated statistics (off by default, optional)\n");
  printf(" -A                 : Only print aggregated statistics (off by default, optional)\n");
  printf(" -b                 : Give this option if you know that tcpdump has dropped packets.\n");
  printf("                    : Statistical methods will be used to compensate where possible.\n");
  printf(" -d                 : Indicate debug level\n");
  printf("                      1 = Only output on reading sender side dump first pass.\n");
  printf("                      2 = Only output on reading sender side second pass.\n");
  printf("                      3 = Only output on reading receiver side.\n");
  printf("                      4 = Only output when comparing sender and receiver.\n");
  printf("                      5 = Print all debug messages.\n");
  exit(0);
}

int main(int argc, char *argv[]){
  char *src_ip = (char*)"";
  char *dst_ip = (char*)"";
  int src_port = 0;
  int dst_port = 0;
  char *sendfn = (char*)""; /* Sender dump file name */
  char *recvfn = (char*)""; /* Receiver dump filename */

  int c;
  Dump *senderDump;

  while(1){
    c = getopt( argc, argv, "s:r:p:q:f:m:n:o:g:d:u:aAtb");
    if(c == -1) break;

    switch(c){
    case 's':
      src_ip = optarg;
      break;
    case 'r':
      dst_ip = optarg;
      break;
    case 'p':
      dst_port = atoi(optarg);
      break;
    case 'q':
      src_port = atoi(optarg);
      break;
    case 'm':
      GlobOpts::sendNatIP = optarg;
      break;
    case 'n':
      GlobOpts::recvNatIP = optarg;
      break;
    case 'f':
      sendfn = optarg;
      break;
    case 'g':
      recvfn = optarg;
      GlobOpts::withRecv = true;
      break;
    case 't':
      GlobOpts::transport = true;
      break;
    case 'u':
      GlobOpts::prefix = optarg;
      GlobOpts::genRFiles = true;
      break;
    case 'a':
      GlobOpts::aggregate = true;
      break;
    case 'A':
      GlobOpts::aggOnly = true;
      GlobOpts::aggregate = true;
      break;
    case 'b':
      GlobOpts::incTrace = true;
      break;
    case 'd':
      GlobOpts::debugLevel = atoi(optarg);
      break;
    case '?':
      if (optopt == 'c')
	fprintf(stderr, "Option -%c requires an argument\n", optopt);
      else if(isprint(optopt))
	fprintf(stderr,"Unknown option -%c\n", optopt);
      else
	fprintf(stderr, "Something is really wrong\n");

      return 1;
    default:
      break;
    }
  }
  /* TODO Exit if required options are not given */ 
  if(argc < 4){
    usage(argv[0]);
  }
   
  if(GlobOpts::debugLevel < 0)
    cerr << "debugLevel = " << GlobOpts::debugLevel << endl;
  
  if(GlobOpts::incTrace){
    cout << "Incomplete trace option has been specified." << endl << "Beware that maximum and minimum values may be erroneous." << endl << "Statistical methods will be applied to compensate where this is possible." << endl;
  }

  /* Create Dump - object */
  senderDump = new Dump(src_ip, dst_ip, src_port, dst_port, sendfn);
  senderDump->analyseSender();
  
  if(GlobOpts::genRFiles)
    senderDump->genRFiles();
  
  if (GlobOpts::withRecv)
    senderDump->processRecvd(recvfn);
  
  senderDump->printDumpStats();

  return 0;
}

