/*************************************************************************************
**************************************************************************************
**                                                                                  **
**  analyseDASH - Tool for analysing sets of tcpdumps to understand how DASH flows  **
**                behave per segment.                                               **
**                                                                                  **
**  Copyright (C) 2007     Andreas Petlund  - andreas@petlund.no                    **
**                     and Kristian Evensen - kristrev@ifi.uio.no                   **
**                2015     Carsten Griwodz  - griff@simula.no                       **
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

#include "analyseDASH.h"
#include "common.h"
#include "fourTuple.h"
#include "Dump.h"
// #include "color_print.h"
#include <getopt.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sstream>
#include <stdio.h>
#include <string.h>

using namespace std;


static struct option long_options[] = {
	{"sender-dump",              	required_argument, 0, 's'},
	{"receiver-dump",            	required_argument, 0, 'r'},
	{"output-dir",               	required_argument, 0, 'o'},
	{"prefix",                   	required_argument, 0, 'u'},
	{0, 0, 0, 0}
};

string OPTSTRING;
string usage_str;

void parse_print_packets(char* optarg)
{
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

/** Parse the long_options data structure to ensure an optstring that
 *  is always up to date.
 */
void make_optstring()
{
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

void usage (char* argv, int exit_status=1 )
{
	printf("Usage: %s [%s] <connection>+\n", argv, usage_str.c_str());

	printf("Required options:\n");
    printf("<connection>         : At least one connection in the form ip:port-ip:port\n");
	printf(" -s <pcap-file>      : Sender-side dumpfile.\n");
	printf("Other options:\n");
	printf(" -r <pcap-file>      : Receiver-side dumpfile.\n");
	printf(" -o <output-dir>     : Output directory to write the result files in.\n");
	printf(" -u <prefix>         : Use <prefix> as filename prefix for output files.\n");
	exit(exit_status);
}

vector<four_tuple_t> connections;
string               sendfn = ""; /* Sender dump file name */
string               recvfn = ""; /* Receiver dump filename */

void parse_cmd_args(int argc, char *argv[])
{
    cerr << "Entering with " << argc << " arguments to parse" << endl;

	int option_index = 0;
	int c;

	while ((c = getopt_long(argc, argv, OPTSTRING.c_str(), long_options, &option_index)) != -1) {
		switch (c) {
		case 's':
			sendfn = optarg;
			break;
		case 'r':
			recvfn = optarg;
			break;
		case 'u':
			GlobOpts::prefix = optarg;
			break;
		case 'o':
			GlobOpts::RFiles_dir = optarg;
			break;
		case '?' :
			printf("Unknown option: -%c\n", c);
			usage(argv[0],-__LINE__);
            break;
		case 'h':
			usage(argv[0],0);
		default:
			break;
		}
	}

	if (sendfn == "") {
        cerr << __FILE__ << ":" << __LINE__ << ": ERROR: no pcap file specified" << endl;
		usage(argv[0],-__LINE__);
	}

    if( argc <= optind )
    {
        cerr << __FILE__ << ":" << __LINE__ << ": ERROR: at least one connection must be specified" << endl;
		usage(argv[0],-__LINE__);
    }

    for( int i=optind; i<argc; i++ )
    {
        four_tuple_t tuple( argv[i] );
        if( not tuple.valid() )
        {
            cerr << __FILE__ << ":" << __LINE__ << ": ERROR: " << argv[i] << " does not specify a valid connection" << endl;
		    usage(argv[0],-__LINE__);
        }
        connections.push_back( tuple );
    }

    cerr << "argc=        " << argc << endl
         << "optind=      " << optind << endl
         << "option_index=" << option_index << endl;
}

int main(int argc, char *argv[])
{
	make_optstring();
	parse_cmd_args(argc, argv);

#if 0
	if(GlobOpts::debugLevel < 0)
		cerr << "debugLevel = " << GlobOpts::debugLevel << endl;
#endif

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
	Dump *senderDump = new Dump( connections, sendfn );
	senderDump->analyseSender();

#if 0
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
#endif

	return 0;
}

