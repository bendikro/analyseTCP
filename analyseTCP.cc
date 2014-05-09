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
#include "Dump.h"
#include "color_print.h"
#include <getopt.h>
#include <sys/stat.h>
#include <sstream>

vector<string> GlobStats::retrans_filenames;
vector<std::tr1::shared_ptr<vector <LatencyItem> > > GlobStats::ack_latency_vectors;
GlobStats *globStats;

/* Initialize global options */
bool GlobOpts::aggregate          		= false;
bool GlobOpts::aggOnly            		= false;
bool GlobOpts::withRecv           		= false;
bool GlobOpts::withLoss           		= false;
bool GlobOpts::withCDF            		= false;
bool GlobOpts::transport          		= false;
bool GlobOpts::genAckLatencyFiles 		= false;
bool GlobOpts::withThroughput			= false;
string GlobOpts::prefix           		= "";
string GlobOpts::RFiles_dir       		= "";
int GlobOpts::debugLevel          		= 0;
uint64_t GlobOpts::lossAggrMs     		= 1000;
uint64_t GlobOpts::throughputAggrMs 	= 1000;
bool GlobOpts::relative_seq       		= false;
bool GlobOpts::print_packets      		= false;
string GlobOpts::sendNatIP        		= "";
string GlobOpts::recvNatIP        		= "";
bool GlobOpts::connDetails        		= false;
int GlobOpts::verbose             		= 0;
int GlobOpts::max_retrans_stats   		= 6;
string GlobOpts::percentiles      		= "";
int GlobOpts::analyse_start       		= 0;
int GlobOpts::analyse_end         		= 0;
int GlobOpts::analyse_duration    		= 0;
bool GlobOpts::oneway_delay_variance	= false;

string LatencyItem::str() const {
	ostringstream buffer;
	buffer << time_ms << "," << latency;
	//buffer << latency;
	return buffer.str();
}

ofstream& operator<<(ofstream& stream, const LatencyItem& lat) {
	stream << lat.str();
	return stream;
}

bool operator==(const timeval& lhs, const timeval& rhs) {
	return lhs.tv_sec == rhs.tv_sec && lhs.tv_usec == rhs.tv_usec;
}

void warn_with_file_and_linenum(string file, int linenum) {
	cout << "Error at ";
	cout << "File: " << file << " Line: " << linenum  << endl;
}

void exit_with_file_and_linenum(int exit_code, string file, int linenum) {
	warn_with_file_and_linenum(file, linenum);
	exit(exit_code);
}

bool endsWith(const string& s, const string& suffix) {
	return s.rfind(suffix) == (s.size()-suffix.size());
}

#ifdef DEBUG
void test(Dump *d) {
	uint32_t first_seq = 1000;
	uint32_t seq = 2000;
	ulong lastLargestEndSeq = 1999;
	uint32_t largestSeqAbsolute = 999;

	// TEST 1
	printf("\n\nTEST1:\n");
	printf("SEQ 1: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));

	// TEST 2
	first_seq = 4294967000;
	seq = UINT_MAX -50;
	lastLargestEndSeq = UINT_MAX +100;
	largestSeqAbsolute = first_seq + lastLargestEndSeq;
	printf("\n\nTEST2:\n");
	//printf("seq: %u\n", seq);
	printf("first_seq: %u\n", first_seq);
	printf("SEQ 2: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));

	//lastLargestSeqAbsolute

	// TEST 3
	first_seq = 4294967000;
	seq = UINT_MAX + 20;
	lastLargestEndSeq = 10;
	largestSeqAbsolute = first_seq + lastLargestEndSeq;
	printf("\n\nTEST3:\n");
	printf("seq: %u\n", seq);
	printf("first_seq: %u\n", first_seq);
	printf("SEQ 3: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));

	// TEST 4
	first_seq = 4294967000;
	seq = UINT_MAX + 1;
	lastLargestEndSeq = 294;
	largestSeqAbsolute = first_seq + lastLargestEndSeq;
	printf("\n\nTEST4:\n");
	printf("seq: %u\n", seq);
	printf("first_seq: %u\n", first_seq);
	printf("largestSeqAbsolute: %u\n", largestSeqAbsolute);
	printf("SEQ 4: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));

	int i;
	for (i = 0; i < 10; i++) {
		first_seq = 4294967000;
		seq = UINT_MAX + i -1;
		lastLargestEndSeq = 293 + i;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\nTEST %d:\n", i + 5);
		printf("first_seq: %u\n", first_seq);
		printf("seq      : %u\n", seq);
		printf("largestSeqAbsolute: %u\n", largestSeqAbsolute);
		printf("lastLargestEndSeq: %lu\n", lastLargestEndSeq);
		printf("SEQ %d: %lu\n", i + 5, d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));
	}

	// Seq just wrapped, but received out of order (or older packet with unwrapped seq number)
	seq = 4294962347;
	first_seq = 4286361190;
	lastLargestEndSeq = 8609844;
	largestSeqAbsolute = 3739;
	printf("\nTEST %d:\n", i + 5);
	printf("first_seq: %u\n", first_seq);
	printf("seq      : %u\n", seq);
	printf("largestSeqAbsolute: %u\n", largestSeqAbsolute);
	printf("lastLargestEndSeq: %lu\n", lastLargestEndSeq);
	printf("SEQ %d: %lu\n", i + 5, d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute));

	exit(1);
}
#endif

#define OPTSTRING "f:s:g:r:q:p:m:n:o:u:lctL::T::QaAeji::yvkd:h"

void usage (char* argv, int exit_status=1, int help_level=1){
	string s(OPTSTRING);
	string::iterator c = s.begin();

	printf("Usage: %s [-%c", argv, *c++);
	for (; c != s.end(); ++c) {
		if (*c != ':') {
			printf("|-%c", *c);
		}
	}
	printf("]\n");

	printf("Required options:\n");
	printf(" -f <pcap-file>      : Sender-side dumpfile.\n");
	printf("Other options:\n");
	printf(" -s <sender ip>      : Sender ip.\n");
	printf(" -g <pcap-file>      : Receiver-side dumpfile.\n");
	printf(" -r <receiver ip>    : Receiver ip. If not given, analyse all receiver IPs.\n");
	printf(" -q <sender port>    : Sender port. If not given, analyse all sender ports.\n");
	printf(" -p <receiver port>  : Receiver port. If not given, analyse all receiver ports.\n");
	printf(" -m <IP>             : Sender side external NAT address as seen on receiver-side dump\n");
	printf(" -n <IP>             : Receiver side local address as seen on receiver-side dump\n");
	printf(" -o <output-dir>     : Output directory to write the result files in.\n");
	printf(" -u <prefix>         : Use <prefix> as filename prefix for output files.\n");
	printf(" -l                  : Write ACK-based latency values to file.\n");
	printf(" -c                  : Write byte-based latency variation CDF to file.\n");
	printf("                       If -t is not set, application-layer latency variation will be used.\n");
	printf(" -t                  : Use transport-layer delays instead of application-layer (affects -c and -Q)\n");
	printf(" -L<interval>        : Write loss over time to file, aggregated by interval in milliseconds (default is 1000).\n");
	printf("                       This requires a receiver-side dumpfile (option -g).\n");
	if (help_level > 1) {
		printf("                       Columns in output file:\n");
		printf("                         0  interval (time slice)\n");
		printf("                         1  total ranges sent during interval\n");
		printf("                         2  total bytes sent during interval (retransmitted and new data)\n");
		printf("                         3  total bytes of old data sent during interval (retransmitted only)\n");
		printf("                         4  total bytes of new data sent during interval (new data only)\n");
		printf("                         5  ranges lost within interval\n");
		printf("                         6  all bytes lost within interval\n");
		printf("                         7  old bytes lost within interval\n");
		printf("                         8  new bytes lost within interval\n");
		printf("                         9  ranges lost relative to ranges sent within interval\n");
		printf("                         10  all bytes lost relative to all bytes sent within interval\n");
		printf("                         11 old bytes lost relative to all bytes sent within interval\n");
		printf("                         12 new bytes lost relative to all bytes sent within interval\n");
		printf("                         13 old bytes lost relative to all bytes lost within interval\n");
		printf("                         14 new bytes lost relative to all bytes lost within interval\n");
		printf("                         15 ranges lost within interval relative to ranges sent in total\n");
		printf("                         16 all bytes lost within interval relative to bytes sent in total\n");
	}
	printf(" -T<interval>        : Write packet count and byte count over time to file, aggregated by interval in milliseconds (default is 1000).\n");
	if (help_level > 1) {
	printf("                       Columns in output file:\n");
		printf("                         0  interval (time slice)\n");
		printf("                         1  total packets sent within interval\n");
		printf("                         2  bytes sent within interval\n");
		printf("                         3  throughput in bits per second\n");
	}
	printf(" -Q                  : Write sent-times and one-way delay variation (queueing delay) to file.\n");
	printf("                       This will implicitly set option -t.\n");
	printf(" -a                  : Produce aggregated statistics (off by default, optional)\n");
	printf(" -A                  : Only print aggregated statistics.\n");
	printf(" -e                  : List the connections found in the dumpfile.\n");
	printf(" -j                  : Use relative sequence numbers in output.\n");
	printf(" -i<percentiles>     : Calculate the specified percentiles for latency and packet size.\n");
	printf("                       Comma separated list of percentiles, default is 1,25,50,75,99\n");
	if (help_level > 1) {
		printf("                       Example for 90th, 99th and 99.9th: -i90,99,99.9\n");
	}
	printf(" -y                  : Print details for each packet.\n");
	printf("                       This requires a receiver-side dumpfile (option -g).\n");
	printf(" -v                  : Be verbose, print more statistics details. The more v's the more verbose.\n");
	if (help_level > 1) {
		printf("                         v   = Be verbose and print some details.\n");
		printf("                         vv  = Be more verbose and print some more details.\n");
		printf("                         vvv = Be even more verbose and print even more details.\n");
	}
	printf(" -k                  : Use colors when printing.\n");
	printf(" -d<level>           : Indicate debug level (1-5).\n");
	if (help_level > 1) {
		printf("                         1 = Only output on reading sender side dump first pass.\n");
		printf("                         2 = Only output on reading sender side second pass.\n");
		printf("                         3 = Only output on reading receiver side.\n");
		printf("                         4 = Only output when comparing sender and receiver.\n");
		printf("                         5 = Print all debug messages.\n");
	}
	printf(" -h                  : Print this help and quit. More h's means more help.\n");
	printf("\n");
	printf(" --analyse-start=<start>       : Start analysing <start> seconds into the stream(s)\n");
	printf(" --analyse-end=<end>           : Stop analysing <end> seconds before the end of the stream(s)\n");
	printf(" --analyse-duration=<duration> : Stop analysing after <duration> seconds after the start\n");

	if (help_level > 2) {
		printf("\n");
		if (help_level < 4)
			printf("That's all!\n");
		else if (help_level < 5)
			printf("Stop nagging, I've already said what I can.\n");
		else if (help_level < 6)
			printf("I've already been helpful enough, don't you think?\n");
		else if (help_level < 7)
			printf("Come on, dude! Leave me alone.\n");
		else if (help_level < 8)
			printf("Stop!\n");
		else if (help_level <= 9)
			printf("Stop it!\n");
		else if (help_level >= 10)
			printf("...\n");
	}

#ifdef DEBUG
	printf("\nCompiled in DEBUG mode\n");
#endif

	exit(exit_status);
}


static struct option long_options[] = {
	{"src-ip",                   	required_argument, 0, 's'},
	{"dst-ip",                   	required_argument, 0, 'r'},
	{"src-port",                 	required_argument, 0, 'q'},
	{"dst-port",                 	required_argument, 0, 'p'},
	{"src-nat-ip",               	required_argument, 0, 'm'},
	{"dst-nat-ip",              	required_argument, 0, 'n'},
	{"sender-dump",              	required_argument, 0, 'f'},
	{"receiver-dump",            	required_argument, 0, 'g'},
	{"output-dir",               	required_argument, 0, 'o'},
	{"prefix",                   	required_argument, 0, 'u'},
	{"transport-layer",   		 	no_argument,       0, 't'},
	{"latency-variation",        	no_argument,       0, 'c'},
	{"latency-values",           	no_argument,       0, 'l'},
	{"queueing-delay",			 	no_argument,       0, 'Q'},
	{"throughput-interval",         optional_argument, 0, 'T'},
	{"loss-interval",            	optional_argument, 0, 'L'},
	{"percentiles",              	optional_argument, 0, 'i'},
	{"connection-list",          	no_argument,       0, 'e'},
	{"aggregated",               	no_argument,       0, 'a'},
	{"aggregated-only",          	no_argument,       0, 'A'},
	{"relative-sequence-numbers",	no_argument,       0, 'j'},
	{"packet-details",             	no_argument,       0, 'y'},
	{"colored-print",              	no_argument,       0, 'k'},
	{"help",                     	no_argument,       0, 'h'},
	{"verbose",                  	optional_argument, 0, 'v'},
	{"debug",                    	required_argument, 0, 'd'},
	{"analyse-start",            	required_argument, 0, 'S'},
	{"analyse-end",              	required_argument, 0, 'E'},
	{"analyse-duration",         	required_argument, 0, 'D'},
	{0, 0, 0, 0}
};

string src_ip = "";
string dst_ip = "";
string src_port = "";
string dst_port = "";
string sendfn = ""; /* Sender dump file name */
string recvfn = ""; /* Receiver dump filename */

void parse_cmd_args(int argc, char *argv[]) {
	int option_index = 0;
	int c;
	int help_level = 0;

	// Default to disable color prints
	disable_colors = true;

	while ((c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index)) != -1) {
		switch (c) {
		case 's':
			src_ip = optarg;
			break;
		case 'r':
			dst_ip = optarg;
			break;
		case 'p':
			dst_port = string(optarg);
			break;
		case 'q':
			src_port = string(optarg);
			break;
		case 'e':
			GlobOpts::connDetails = true;
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
		case 'L':
			GlobOpts::withLoss = true;
			if (optarg) {
				char *sptr = NULL;
				uint64_t ret = strtoul(optarg, &sptr, 10);
				if (ret == 0 || sptr == NULL || *sptr != '\0') {
					colored_printf(RED, "Option -%c requires a valid integer: '%s'\n", c, optarg);
					usage(argv[0]);
				}
				GlobOpts::lossAggrMs = ret;
			}
			break;
		case 'T':
			GlobOpts::withThroughput = true;
			if (optarg) {
				char *sptr = NULL;
				uint64_t ret = strtoul(optarg, &sptr, 10);
				if (ret == 0 || sptr == NULL || *sptr != '\0') {
					colored_printf(RED, "Option -%c requires a valid integer: '%s'\n", c, optarg);
					usage(argv[0]);
				}
				GlobOpts::throughputAggrMs = ret;
			}
			break;
		case 'i':
			if (optarg)
				GlobOpts::percentiles = string(optarg);
			else
				GlobOpts::percentiles = "1,25,50,75,99";
			break;
		case 'c':
			GlobOpts::withCDF = true;
			break;
		case 't':
			GlobOpts::transport = true;
			break;
		case 'l':
			GlobOpts::genAckLatencyFiles = true;
			break;
		case 'u':
			GlobOpts::prefix = optarg;
			break;
		case 'o':
			GlobOpts::RFiles_dir = optarg;
			break;
		case 'a':
			GlobOpts::aggregate = true;
			break;
		case 'A':
			GlobOpts::aggOnly = true;
			GlobOpts::aggregate = true;
			break;
		case 'j':
			GlobOpts::relative_seq = true;
			break;
		case 'y':
			GlobOpts::print_packets = true;
			break;
		case 'd':
			GlobOpts::debugLevel = atoi(optarg);
			break;
		case 'v':
			GlobOpts::verbose++;
			break;
		case 'k':
			disable_colors = false;
			break;
		case 'S':
			GlobOpts::analyse_start = atoi(optarg);
			break;
		case 'E':
			GlobOpts::analyse_end = atoi(optarg);
			break;
		case 'D':
			GlobOpts::analyse_duration = atoi(optarg);
			break;
		case 'Q':
			GlobOpts::oneway_delay_variance = true;
			GlobOpts::transport = true;
			break;
		case 'h':
			help_level++;
			break;
		case '?' :
			printf("Unknown option: -%c\n", c);
			usage(argv[0]);
		default:
			break;
		}
	}

	if (help_level > 0) {
		usage(argv[0], 0, help_level);
	}

	if (GlobOpts::analyse_end && GlobOpts::analyse_duration) {
		printf("You may only supply either --analyse-end or analyse-duration, not both\n");
		usage(argv[0]);
	}

	if (GlobOpts::withLoss && !GlobOpts::withRecv) {
		printf("Option --loss-interval requires option --receiver-dump\n");
		usage(argv[0]);
	}

	if (GlobOpts::oneway_delay_variance) {
		printf("Option --queueuing-delay is set, setting --transport-layer\n");
		GlobOpts::transport = true;
	}

	if (GlobOpts::aggOnly) {
		GlobOpts::aggregate = true;
	}

	if (sendfn == "") {
		usage(argv[0]);
	}
}

int main(int argc, char *argv[]){

	parse_cmd_args(argc, argv);

	if(GlobOpts::debugLevel < 0)
		cerr << "debugLevel = " << GlobOpts::debugLevel << endl;

	if (GlobOpts::RFiles_dir.length()) {
		if (!endsWith(GlobOpts::RFiles_dir, string("/")))
			GlobOpts::RFiles_dir += "/";

		struct stat sb;
		if (!(stat(GlobOpts::RFiles_dir.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode))) {
			printf("Output directory does not exist!\n");
			exit(1);
		}

		GlobOpts::prefix = GlobOpts::RFiles_dir + GlobOpts::prefix;
	}

	// Define once to run the constructor of GlobStats
	GlobStats s;
	globStats = &s;

	/* Create Dump - object */
	Dump *senderDump = new Dump(src_ip, dst_ip, src_port, dst_port, sendfn);
	//test(senderDump);
	senderDump->analyseSender();

	if (GlobOpts::withRecv) {
		senderDump->processRecvd(recvfn);
	}

	/* Traverse ranges in senderDump and compare to
	   corresponding bytes / ranges in receiver ranges
	   place timestamp diffs in buckets */
	senderDump->calculateRetransAndRDBStats();

	if (GlobOpts::withRecv && (GlobOpts::withCDF || GlobOpts::oneway_delay_variance || GlobOpts::print_packets)) {

		assert((!GlobOpts::oneway_delay_variance || (GlobOpts::oneway_delay_variance && GlobOpts::transport))
				&& "One-way delay variance was chosen, but delay is set to application layer");

		senderDump->calculateLatencyVariation();

		if (GlobOpts::withCDF) {
			senderDump->makeByteLatencyVariationCDF();

			if (!GlobOpts::aggOnly) {
				senderDump->writeByteLatencyVariationCDF();
			}

			if (GlobOpts::aggregate){
				senderDump->writeAggByteLatencyVariationCDF();
			}
		}

		if (GlobOpts::oneway_delay_variance) {
			senderDump->writeSentTimesAndQueueingDelayVariance();
		}
	}

	if (GlobOpts::genAckLatencyFiles)
		senderDump->genAckLatencyFiles();

	if (GlobOpts::withThroughput)
		senderDump->writeByteCountGroupedByInterval();

	if (GlobOpts::withLoss)
		senderDump->write_loss_to_file();

	if (GlobOpts::connDetails) {
		senderDump->printConns();
		return 0;
	}

	if (GlobOpts::print_packets) {
		senderDump->printPacketDetails();
	}

	senderDump->printStatistics();

	senderDump->printDumpStats();
	senderDump->free_resources();

	delete senderDump;

	return 0;
}

