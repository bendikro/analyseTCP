#include "common.h"

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
vector <pair<uint64_t, uint64_t> > GlobOpts::print_packets_pairs;
string GlobOpts::sendNatIP        		= "";
string GlobOpts::recvNatIP        		= "";
bool GlobOpts::connDetails        		= false;
int GlobOpts::verbose             		= 0;
bool GlobOpts::validate_ranges    		= true;
int GlobOpts::max_retrans_stats   		= 6;
string GlobOpts::percentiles      		= "";
int GlobOpts::analyse_start       		= 0;
int GlobOpts::analyse_end         		= 0;
int GlobOpts::analyse_duration    		= 0;
bool GlobOpts::oneway_delay_variance	= false;

string LatencyItem::str() const {
	ostringstream buffer;
	buffer << time_ms << "," << latency;
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