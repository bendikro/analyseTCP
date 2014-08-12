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
#include "common.h"
#include "Dump.h"
#include "color_print.h"
#include <getopt.h>
#include <sys/stat.h>
#include <sstream>

static struct option long_options[] = {
	{"sender-dump",              	required_argument, 0, 'f'},
	{"src-ip",                   	required_argument, 0, 's'},
	{"src-port",                 	required_argument, 0, 'q'},
	{"dst-ip",                   	required_argument, 0, 'r'},
	{"dst-port",                 	required_argument, 0, 'p'},
	{"src-nat-ip",               	required_argument, 0, 'm'},
	{"dst-nat-ip",              	required_argument, 0, 'n'},
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
	{"packet-details",             	optional_argument, 0, 'y'},
	{"colored-print",              	no_argument,       0, 'k'},
	{"help",                     	no_argument,       0, 'h'},
	{"validate-ranges",            	no_argument,       0, 'V'},
	{"verbose",                  	no_argument, 	   0, 'v'},
	{"debug",                    	required_argument, 0, 'd'},
	{"analyse-start",            	required_argument, 0, 'S'},
	{"analyse-end",              	required_argument, 0, 'E'},
	{"analyse-duration",         	required_argument, 0, 'D'},
	{0, 0, 0, 0}
};

string OPTSTRING;
string usage_str;

void parse_print_packets(char* optarg) {
	std::istringstream ss(optarg);
	std::string token;
	uint64_t last_range_seq = 0;
	uint64_t num;
	size_t range_i;
	while (std::getline(ss, token, ',')) {
		range_i = token.find("-");
		if (range_i == string::npos) {
			// Add just this seqnum
			istringstream(token) >> num;
			GlobOpts::print_packets_pairs.push_back(pair<uint64_t, uint64_t>(num, num));
		}
		else {
			// e.g. '-1000'
			if (range_i == 0) {
				istringstream(token.substr(1, string::npos)) >> num;
				GlobOpts::print_packets_pairs.push_back(make_pair(last_range_seq, num));
				last_range_seq = num + 1;
			}
			else if (range_i == token.size() - 1) {
				string f1 = token.substr(0, range_i);
				GlobOpts::print_packets_pairs.push_back(make_pair(std::stoul(f1), (numeric_limits<uint64_t>::max)()));
			}
			else {
				// We have a range with two values
				string f1 = token.substr(0, token.find("-"));
				string f2 = token.substr(token.find("-")+1, string::npos);
				istringstream(token.substr(1, string::npos)) >> num;
				GlobOpts::print_packets_pairs.push_back(make_pair(std::stoul(f1), std::stoul(f2)));
				last_range_seq = std::stoul(f2) + 1;
			}
		}
		istringstream(token) >> num;
	}
}

void make_optstring() {
/*
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
*/
	stringstream usage_tmp, opts;
	int i = 0;
	for (; long_options[i].name != 0; i++) {
		if (i)
			usage_tmp << "|";
		usage_tmp << "-" << ((char) long_options[i].val);

		opts << (char) long_options[i].val;
		if (long_options[i].has_arg == no_argument)
			continue;
		opts << ':';
		if (long_options[i].has_arg == optional_argument)
			opts << ':';
	}
	OPTSTRING = opts.str();
	usage_str = usage_tmp.str();
}

void usage (char* argv, int exit_status=1, int help_level=1){
	printf("Usage: %s [%s]\n", argv, usage_str.c_str());

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
	printf(" -y<seq-num-range>   : Print details for each packet. Provide an option sequence number or range of seq to print\n");
	printf(" -v                  : Be verbose, print more statistics details. The more v's the more verbose.\n");
	if (help_level > 1) {
		printf("                         v   = Be verbose and print some details.\n");
		printf("                         vv  = Be more verbose and print some more details.\n");
		printf("                         vvv = Be even more verbose and print even more details.\n");
	}
	printf(" -k                  : Use colors when printing.\n");
	printf(" -V                  : Disable validation of the data in the ranges.\n");
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

	while ((c = getopt_long(argc, argv, OPTSTRING.c_str(), long_options, &option_index)) != -1) {
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
			if (optarg)
				parse_print_packets(optarg);
			break;
		case 'd':
			GlobOpts::debugLevel = atoi(optarg);
			break;
		case 'V':
			GlobOpts::validate_ranges = false;
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
	make_optstring();
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

	if (GlobOpts::withThroughput) {
		senderDump->writeByteCountGroupedByInterval();
		senderDump->writePacketByteCountAndITT();
	}

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

