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

vector<string> GlobStats::retrans_filenames;
vector<vector <int> *> GlobStats::ack_latency_vectors;
GlobStats *globStats;

/* Initialize global options */
bool GlobOpts::aggregate        = false;
bool GlobOpts::aggOnly          = false;
bool GlobOpts::withRecv         = false;
bool GlobOpts::withLoss         = false;
bool GlobOpts::withCDF          = false;
bool GlobOpts::transport        = false;
bool GlobOpts::genRFiles        = false;
string GlobOpts::prefix         = "";
string GlobOpts::RFiles_dir     = "";
int GlobOpts::debugLevel        = 0;
int GlobOpts::lossAggrSeconds   = 1;
bool GlobOpts::relative_seq     = false;
bool GlobOpts::print_packets    = false;
string GlobOpts::sendNatIP      = "";
string GlobOpts::recvNatIP      = "";
bool GlobOpts::connDetails      = false;
int GlobOpts::verbose           = 0;
int GlobOpts::max_retrans_stats = 6;
string GlobOpts::percentiles    = "1,25,50,75,99";

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

void usage (char* argv){
	printf("Usage: %s [-s|r|p|f|g|t|u|m|n|a|A|e|u|d|l|j|y|o|k]\n", argv);
	printf("Required options:\n");
	printf(" -s <sender ip>     : Sender ip.\n");
	printf(" -f <pcap-file>     : Sender-side dumpfile.\n");
	printf("Other options:\n");
	printf(" -r <receiver ip>   : Receiver ip. If not given, analyse all receiver IPs\n");
	printf(" -q <sender port>   : Sender port. If not given, analyse all sender ports\n");
	printf(" -p <receiver port> : Receiver port. If not given, analyse all receiver ports\n");
	printf(" -g <pcap-file>     : Receiver-side dumpfile\n");
	printf(" -c                 : Write CDF stats to file.\n");
	printf(" -l<interval>       : Write loss over time to file with optional time slice interval (Default is 1 second).\n");
	printf(" -t                 : Calculate transport-layer delays\n");
	printf("                    : (if not set, application-layer delay is calculated)\n");
	printf(" -u<prefix>         : Write statistics to comma-separated files (for use with R)\n");
	printf("                      Optional argument <prefix> assigns an output filename prefix (No space between option and argument).\n");
	printf(" -o <output-dir>    : Directory to write the statistics results (implies -u)\n");
	printf(" -m <IP>            : Sender side external NAT address (as seen on recv dump)\n");
	printf(" -n <IP>            : Receiver side local address (as seen on recv dump)\n");
	printf(" -a                 : Produce aggregated statistics (off by default, optional)\n");
	printf(" -A                 : Only print aggregated statistics (off by default, optional)\n");
	printf(" -e                 : Only print the connections found in the trace\n");
	printf(" -j                 : Print relative sequence numbers.\n");
	printf(" -i <percentiles>   : Calculate the specified percentiles (Comma separated list of percentiles).\n");
	printf(" -y                 : Print details for each packet (requires receiver side dump).\n");
	printf(" -v                 : Be verbose, print more statistics details\n");
	printf(" -k                 : Use colors when printing\n");
	printf(" -d                 : Indicate debug level\n");
	printf("                      1 = Only output on reading sender side dump first pass.\n");
	printf("                      2 = Only output on reading sender side second pass.\n");
	printf("                      3 = Only output on reading receiver side.\n");
	printf("                      4 = Only output when comparing sender and receiver.\n");
	printf("                      5 = Print all debug messages.\n");
	exit(0);
}

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

int main(int argc, char *argv[]){
	string src_ip = "";
	string dst_ip = "";
	string src_port = "";
	string dst_port = "";
	string sendfn = ""; /* Sender dump file name */
	string recvfn = ""; /* Receiver dump filename */

	int c;
	Dump *senderDump;
	// Default to disable color prints
	disable_colors = true;

	while (1){
		c = getopt(argc, argv, "s:r:p:q:f:m:n:o:g:d:i:u::l::o:aAetjychvk");
		if (c == -1)
			break;

		switch(c) {
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
		case 'l':
			GlobOpts::withLoss = true;
			if (optarg) {
				char *sptr = NULL;
				long int ret = strtol(optarg, &sptr, 10);
				if (ret <= 0 || sptr == NULL || *sptr != '\0') {
					colored_printf(RED, "Option -l requires a valid integer: '%s'\n", optarg);
					usage(argv[0]);
				}
				GlobOpts::lossAggrSeconds = ret;
			}
			break;
		case 'i':
			GlobOpts::percentiles = string(optarg);
			break;
		case 'c':
			GlobOpts::withCDF = true;
			break;
		case 't':
			GlobOpts::transport = true;
			break;
		case 'u': {
			GlobOpts::genRFiles = true;
			if (optarg) {
				GlobOpts::prefix = optarg;
			}
		} break;
		case 'o':
			GlobOpts::genRFiles = true;
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
			GlobOpts::verbose = 1;
			break;
		case 'k':
			disable_colors = false;
			break;
		case 'h':
			usage(argv[0]);
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

	if (GlobOpts::RFiles_dir.length()) {
		if (!endsWith(GlobOpts::RFiles_dir, string("/")))
			GlobOpts::RFiles_dir += "/";
		GlobOpts::prefix = GlobOpts::RFiles_dir + GlobOpts::prefix;
	}

	// Define once to run the constructor of GlobStats
	GlobStats s;
	globStats = &s;

	/* Create Dump - object */
	senderDump = new Dump(src_ip, dst_ip, src_port, dst_port, sendfn);
	//test(senderDump);
	senderDump->analyseSender();

	if (GlobOpts::genRFiles)
		senderDump->genRFiles();

	if (GlobOpts::withRecv) {
		senderDump->processRecvd(recvfn);
	}

	if (GlobOpts::connDetails) {
		senderDump->printConns();
		return 0;
	}

	senderDump->write_loss_to_file();

	if ((GlobOpts::print_packets)) {
		senderDump->printPacketDetails();
	}

	senderDump->printStatistics();

	senderDump->printDumpStats();
	senderDump->free_resources();

	delete senderDump;

	return 0;
}

