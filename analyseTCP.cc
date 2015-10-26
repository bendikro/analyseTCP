/*************************************************************************************
**************************************************************************************
**                                                                                  **
**  analyseTCP - Tool for analysing tcpdump files with regard to latency.           **
**                                                                                  **
**  Copyright (C) 2007       Andreas Petlund        - andreas@petlund.no            **
**                           Kristian Evensen       - kristrev@ifi.uio.no           **
**                2012-2015  Bendik Rønning Opstad  - bendikro@gmail.com            **
**                           Jonas Sæther Markussen - jonassm@ifi.uio.no            **
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

#include "common.h"
#include "Dump.h"
#include "Statistics.h"
#include "color_print.h"
#include "util.h"
#include <getopt.h>
#include <sys/stat.h>

#define OPT_PORT 400
#define OPT_ANALYSE_START 401
#define OPT_ANALYSE_END 402
#define OPT_ANALYSE_DURATION 403
#define OPT_SOJOURN_TIME_INPUT 404

static option long_options[] = {
	{"sender-dump",                 required_argument, 0, 'f'},
	{"src-ip",                      required_argument, 0, 's'},
	{"src-port",                    required_argument, 0, 'q'},
	{"dst-ip",                      required_argument, 0, 'r'},
	{"dst-port",                    required_argument, 0, 'p'},
	{"src-nat-ip",                  required_argument, 0, 'm'},
	{"dst-nat-ip",                  required_argument, 0, 'n'},
	{"receiver-dump",               required_argument, 0, 'g'},
	{"output-dir",                  required_argument, 0, 'o'},
	{"prefix",                      required_argument, 0, 'u'},
	{"transport-layer",             no_argument,       0, 't'},
	{"latency-variation",           no_argument,       0, 'c'},
	{"latency-values",              no_argument,       0, 'l'},
	{"per-packet-stats",            no_argument,       0, 'P'},
	{"per-segment-stats",           no_argument,       0, 'S'},
	{"queueing-delay",              no_argument,       0, 'Q'},
	{"throughput-interval",         optional_argument, 0, 'T'},
	{"loss-interval",               optional_argument, 0, 'L'},
	{"percentiles",                 optional_argument, 0, 'i'},
	{"print-conns",                 no_argument,       0, 'e'},
	{"write-conns",                 no_argument,       0, 'E'},
	{"aggregated",                  no_argument,       0, 'a'},
	{"aggregated-only",             no_argument,       0, 'A'},
	{"relative-sequence-numbers",   no_argument,       0, 'j'},
	{"packet-details",              optional_argument, 0, 'y'},
	{"colored-print",               no_argument,       0, 'k'},
	{"help",                        no_argument,       0, 'h'},
	{"validate-ranges",             no_argument,       0, 'V'},
	{"look-for-get-request",        no_argument,       0, 'G'},
	{"verbose",                     optional_argument, 0, 'v'},
	{"debug",                       required_argument, 0, 'd'},
	{"analyse-start",               required_argument, 0, OPT_ANALYSE_START},
	{"analyse-end",                 required_argument, 0, OPT_ANALYSE_END},
	{"analyse-duration",            required_argument, 0, OPT_ANALYSE_DURATION},
	{"tcp-port",                    required_argument, 0, OPT_PORT},
	{"sojourn-time-input",          required_argument, 0, OPT_SOJOURN_TIME_INPUT},
	{0, 0, 0, 0}
};

void usage(char* argv, string usage_str, int exit_status=1, int help_level=1)
{
	printf("Usage: %s [%s]\n", argv, usage_str.c_str());

	printf("Required options:\n");
	printf(" -f <pcap-file>      : Sender-side dumpfile.\n");
	printf("Other options:\n");
	printf(" -s <sender ip>      : Sender ip.\n");
	printf(" -g <pcap-file>      : Receiver-side dumpfile.\n");
	printf(" -r <receiver ip>    : Receiver ip. If not given, analyse all receiver IPs.\n");
	printf(" -q <sender port>    : Sender port. If not given, analyse all sender ports. Port range may be specified with <start>-<end>\n");
	printf(" -p <receiver port>  : Receiver port. If not given, analyse all receiver ports. Port range may be specified with <start>-<end>\n");
	printf(" -m <IP>             : Sender side external NAT address as seen on receiver-side dump\n");
	printf(" -n <IP>             : Receiver side local address as seen on receiver-side dump\n");
	printf(" -o <output-dir>     : Output directory to write the result files in.\n");
	printf(" -u <prefix>         : Use <prefix> as filename prefix for output files.\n");

	printf(" -a                  : Produce aggregated statistics (off by default, optional)\n");
	printf(" -A                  : Only print aggregated statistics.\n");
	printf(" -e                  : List the connections found in the dumpfile.\n");

	printf("\nStatistics file output options:\n");
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
	printf(" -P                  : Write per-packet stats to file.\n");
	printf(" -S                  : Write per-segment stats to file (This requires sojourn data input with options '--sojourn-time-input').\n");
	printf(" -E                  : Write per-connection stats to file.\n");

	printf("\nMisc options:\n");
	printf(" -i<percentiles>     : Calculate and print to terminal the specified percentiles for packet payload size, latency and ITT.\n");
	printf("                       Comma separated list of percentiles, default is 1,25,50,75,99\n");
	if (help_level > 1) {
		printf("                       Example for 90th, 99th and 99.9th: -i90,99,99.9\n");
	}
	printf(" -y<seq-num-range>   : Print details for each packet. Provide an optional (relative) sequence number or range of seqs to print.\n"
		   "                       '-y5000':      The packet starting with seq == 5000\n"
		   "                       '-y-5000':     All packets with seq <= 5000\n"
		   "                       '-y2000-5000': All packets with seq >= 2000 && seq <= 5000\n"
		   "                       '-y2000-':     All packets with seq >= 2000\n"
		   "                       '-y2000-5000,10000-11000': All packets with (seq >= 2000 && seq <= 5000) || (seq >= 10000 && seq <= 11000)\n"
		);
	printf(" -G                  : Look for GET request in the packet payload. (experimental)\n");
	printf(" -j                  : Use relative sequence numbers in terminal output from option -y.\n");
	printf(" -v<level>           : Control verbose level. v0 hides most output, v3 gives maximum verbosity.\n");
	printf(" -k                  : Use colors in terminal output.\n");
	printf(" -V                  : Disable validation of the data in the ranges.\n");
	printf(" -d<level><type>     : Indicate debug level (1-5) (Default=1) and an optional parameter (s/r) indicating if only debug\n"
		   "                       messages from either sender side or receiver side parsing should be printed.\n");
	if (help_level > 1) {
		printf("                         1 = Only output on reading sender side dump first pass.\n");
		printf("                         2 = Only output on reading sender side second pass.\n");
		printf("                         3 = Only output on reading receiver side.\n");
		printf("                         4 = Only output when comparing sender and receiver.\n");
		printf("                         5 = Print all debug messages.\n");
	}
	printf(" -h                  : Print this help and quit. More h's means more help.\n");
	printf("\n");
	printf(" --analyse-start=<start>          : Start analysing <start> seconds into the stream(s)\n");
	printf(" --analyse-end=<end>              : Stop analysing <end> seconds before the end of the stream(s)\n");
	printf(" --analyse-duration=<duration>    : Stop analysing after <duration> seconds after the start\n");
	printf(" --tcp-port=<port>                : Sender or receiver port, combines -q and -p\n");
	printf(" --sojourn-time-input=<filename>  : Text file containing timestamp and sequence number for data segments when entering the kernel.\n");

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
string tcp_port = "";
string sendfn = ""; /* Sender dump file name */
string recvfn = ""; /* Receiver dump filename */

long next_digit(char *str, char **endptr, long *result) {
	errno = 0;    /* To distinguish success/failure after call */
	*result = strtol(str, endptr, 10);

	long LONG_MIN = std::numeric_limits<long>::min();
	long LONG_MAX = std::numeric_limits<long>::max();

	/* Check for various possible errors */
	if ((errno == ERANGE && (*result == LONG_MAX || *result == LONG_MIN))
	    || (errno != 0 && *result == 0)) {
		return -1;
	}

	// No digits found
	if (*endptr == str) {
		return 0;
	}
	return 1;
}

long next_int(char **str) {
	char *endptr;
	long result;

	long ret = next_digit(*str, &endptr, &result);

	if (ret == -1) {
		colored_fprintf(stderr, RED, "Failed to parse '%s'\n", *str);
		perror("strtol");
		return -1;
	}
	else if (ret == 0) {
		colored_fprintf(stderr, RED, "No digits found in '%s'\n", *str);
		return -1;
	}

	*str = endptr;
	return result;
}


void parse_debug_level(char *optargs) {

	long result = next_int(&optargs);
	if (result == -1) {
		fprintf(stderr, "Invalid argument to option debug: '%s'\n", optargs);
		exit(1);
	}
	GlobOpts::debugLevel = (int) result;
	if (*optargs == 's') {
		GlobOpts::debugReceiver = false;
	} else if (*optargs == 'r') {
		GlobOpts::debugSender = false;
	}
}


void parse_cmd_args(int argc, char *argv[], string OPTSTRING, string usage_str) {
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
			if ( not tcp_port.empty())
			{
				colored_printf(RED, "-p cannot be combined with --tcp-port, ignoring -p\n");
				dst_port = "";
			}
			break;
		case 'q':
			src_port = string(optarg);
			if (!tcp_port.empty())
			{
				colored_printf(RED, "-q cannot be combined with --tcp-port, ignoring -q\n");
				src_port = "";
			}
			break;
		case OPT_PORT :
			tcp_port = string(optarg);
			if (!dst_port.empty())
			{
				colored_printf(RED, "--tcp-port cannot be combined with -p, ignoring --tcp-port\n");
				tcp_port = "";
			}
			else if (!src_port.empty())
			{
				colored_printf(RED, "--tcp-port cannot be combined with -q, ignoring --tcp-port\n");
				tcp_port = "";
			}
			break;
		case OPT_SOJOURN_TIME_INPUT:
			GlobOpts::sojourn_time_file = string(optarg);
			break;
		case 'e':
			GlobOpts::connDetails = true;
			break;
		case 'E':
			GlobOpts::writeConnDetails = true;
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
					usage(argv[0], usage_str);
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
					usage(argv[0], usage_str);
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
		case 'P':
			GlobOpts::genPerPacketStats = true;
			break;
		case 'S':
			GlobOpts::genPerSegmentStats = true;
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
				parse_print_packets();
			break;
		case 'G':
			GlobOpts::look_for_get_request = true;
			break;
		case 'd':
			parse_debug_level(optarg);
			break;
		case 'V':
			GlobOpts::validate_ranges = false;
			break;
		case 'v':
			if (optarg) {
				if (isNumeric(optarg, 10)) {
					GlobOpts::verbose = atoi(optarg);
				} else {
					for (uint32_t i = 0; i < strlen(optarg); i++) {
						if (optarg[i] == 'v') {
							GlobOpts::verbose++;
						} else {
							colored_printf(RED, "Invalid optional argument to verbose option: '%s'\n", optarg);
						}
					}
				}
			} else {
				GlobOpts::verbose++;
			}
			break;
		case 'k':
			disable_colors = false;
			break;
		case OPT_ANALYSE_START:
			GlobOpts::analyse_start = atoi(optarg);
			break;
		case OPT_ANALYSE_END:
			GlobOpts::analyse_end = atoi(optarg);
			break;
		case OPT_ANALYSE_DURATION:
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
			usage(argv[0], usage_str);
		default:
			break;
		}
	}

	if (help_level > 0) {
		usage(argv[0], usage_str, 0, help_level);
	}

	if (GlobOpts::analyse_end && GlobOpts::analyse_duration) {
		printf("You may only supply either --analyse-end or analyse-duration, not both\n");
		usage(argv[0], usage_str);
	}

	if (GlobOpts::withLoss && !GlobOpts::withRecv) {
		printf("Option --loss-interval requires option --receiver-dump\n");
		usage(argv[0], usage_str);
	}

	if (GlobOpts::oneway_delay_variance) {
		printf("Option --queueuing-delay is set, setting --transport-layer\n");
		GlobOpts::transport = true;
	}

	if (GlobOpts::aggOnly) {
		GlobOpts::aggregate = true;
	}

	if (sendfn == "") {
		usage(argv[0], usage_str);
	}
}

int main(int argc, char *argv[]) {
	pair <string,string> ret = make_optstring(long_options);
	parse_cmd_args(argc, argv, ret.first, ret.second);

	if (GlobOpts::debugLevel < 0)
		cerr << "debugLevel = " << GlobOpts::debugLevel << endl;

	if (GlobOpts::verbose < 1)
		cerr << "verbose = " << GlobOpts::verbose << endl;

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

	/* Create Dump - object */
	Dump *senderDump = new Dump(src_ip, dst_ip, src_port, dst_port, tcp_port, sendfn);
	senderDump->analyseSender();

	if (GlobOpts::withRecv) {
		senderDump->processRecvd(recvfn);
	}

	if (not GlobOpts::sojourn_time_file.empty())
		senderDump->calculateSojournTime();

	/* Traverse ranges in senderDump and compare to
	   corresponding bytes / ranges in receiver ranges
	   place timestamp diffs in buckets */
	senderDump->calculateRetransAndRDBStats();

	Statistics stats(*senderDump);

	if (GlobOpts::withRecv && (GlobOpts::withCDF || GlobOpts::oneway_delay_variance || GlobOpts::print_packets)) {

		assert((!GlobOpts::oneway_delay_variance || (GlobOpts::oneway_delay_variance && GlobOpts::transport))
				&& "One-way delay variance was chosen, but delay is set to application layer");

		senderDump->calculateLatencyVariation();

		if (GlobOpts::withCDF) {
			stats.makeByteLatencyVariationCDF();

			if (!GlobOpts::aggOnly) {
				stats.writeByteLatencyVariationCDF();
			}
			if (GlobOpts::aggregate) {
				stats.writeAggByteLatencyVariationCDF();
			}
		}

		if (GlobOpts::oneway_delay_variance) {
			stats.writeSentTimesAndQueueingDelayVariance();
		}
	}

	if (GlobOpts::genAckLatencyFiles) {
		stats.writeAckLatency();
	}

	if (GlobOpts::genPerPacketStats) {
		stats.writePerPacketStats();
	}

	if (GlobOpts::genPerSegmentStats) {
		stats.writePerSegmentStats();
	}

	if (GlobOpts::withThroughput) {
		stats.writeByteCountGroupedByInterval();
		stats.writePacketByteCountAndITT();
	}

	if (GlobOpts::withLoss) {
		stats.writeLossStats();
	}

	if (GlobOpts::writeConnDetails) {
		stats.writeConnStats();
	}

	if (GlobOpts::connDetails) {
		stats.printConns();
		return 0;
	}

	if (GlobOpts::print_packets) {
		senderDump->printPacketDetails();
	}

	if (GlobOpts::verbose) {
		stats.printStatistics();
	}
	stats.printDumpStats();

	delete senderDump;
	return 0;
}
