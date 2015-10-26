#include "common.h"
#include <stdarg.h>
#include <string.h>

/* Initialize global options */
bool GlobOpts::aggregate                = false;
bool GlobOpts::aggOnly                  = false;
bool GlobOpts::withRecv                 = false;
bool GlobOpts::withLoss                 = false;
bool GlobOpts::withCDF                  = false;
bool GlobOpts::transport                = false;
bool GlobOpts::genAckLatencyFiles       = false;
bool GlobOpts::genPerPacketStats        = false;
bool GlobOpts::genPerSegmentStats       = false;
bool GlobOpts::withThroughput           = false;
string GlobOpts::prefix                 = "";
string GlobOpts::RFiles_dir             = "";
int GlobOpts::debugLevel                = 1;
bool GlobOpts::debugSender              = true;
bool GlobOpts::debugReceiver            = true;
uint64_t GlobOpts::lossAggrMs           = 1000;
uint64_t GlobOpts::throughputAggrMs     = 1000;
bool GlobOpts::relative_seq             = false;
bool GlobOpts::print_packets            = false;
string GlobOpts::sendNatIP              = "";
string GlobOpts::recvNatIP              = "";
bool GlobOpts::connDetails              = false;
bool GlobOpts::writeConnDetails         = false;
int GlobOpts::verbose                   = 1;
bool GlobOpts::validate_ranges          = true;
int GlobOpts::max_retrans_stats         = 6;
string GlobOpts::percentiles            = "";
int GlobOpts::analyse_start             = 0;
int GlobOpts::analyse_end               = 0;
long GlobOpts::analyse_duration         = 0;
string GlobOpts::sojourn_time_file      = "";
bool GlobOpts::oneway_delay_variance    = false;
bool GlobOpts::look_for_get_request     = false;
vector <pair<uint64_t, uint64_t> > GlobOpts::print_packets_pairs;
bool GlobOpts::conn_key_debug           = false;
	/* Debug warning prints */
bool GlobOpts::print_payload_mismatch_warn = true;
bool GlobOpts::print_timestamp_mismatch_warn = true;

bool operator==(const timeval& lhs, const timeval& rhs) {
	return lhs.tv_sec == rhs.tv_sec && lhs.tv_usec == rhs.tv_usec;
}


void warn_with_file_and_linenum(string file, int linenum) {
	cerr << "Error at ";
	cerr << "File: " << file << " Line: " << linenum  << endl;
}

void exit_with_file_and_linenum(int exit_code, string file, int linenum) {
	warn_with_file_and_linenum(file, linenum);
	exit(exit_code);
}

bool endsWith(const string& s, const string& suffix) {
	return s.rfind(suffix) == (s.size()-suffix.size());
}

/*
  Debug colored printf
*/
void _dclprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, va_list args) {
	if (type == DSENDER && !DEBUGL_SENDER(debug_level))
		return;
	else if (type == DRECEIVER && !DEBUGL_RECEIVER(debug_level))
		return;

	size_t fmt_len = strlen(format) + PREFIX_LEN;
	char *d_format = (char*) malloc(fmt_len);
	snprintf(d_format, fmt_len, DEBUG_PREFIX_FMT, debug_level);
	strcat(d_format, format);
	_colored_fprintf(stream, 1000, fg_color, d_format, args);
}

void dclprintf(enum debug_type type, int debug_level, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_dclprintf(stdout, type, debug_level, fg_color, format, args);
	va_end(args);
}

void dclfprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_dclprintf(stream, type, debug_level, fg_color, format, args);
	va_end(args);
}

/*
  Debug printf
*/
void dprintf(enum debug_type type, int debug_level, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_dclprintf(stdout, type, debug_level, NO_COLOR, format, args);
	va_end(args);
}

/*
  Debug fprintf
*/
void dfprintf(FILE *stream, enum debug_type type, int debug_level, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_dclprintf(stream, type, debug_level, NO_COLOR, format, args);
	va_end(args);
}

/*
  Verbose printf
*/
void vbprintf(int verbose_level, const char *format, ...) {
	if (GlobOpts::verbose > verbose_level) {
		return;
	}
	va_list args;
	va_start(args, format);
	_colored_fprintf(stdout, 1000, NO_COLOR, format, args);
	va_end(args);
}

/*
  Verbose colored printf
*/
void vbclprintf(int verbose_level, int fg_color, const char *format, ...) {
	if (GlobOpts::verbose > verbose_level) {
		return;
	}
	va_list args;
	va_start(args, format);
	_colored_fprintf(stdout, 1000, fg_color, format, args);
	va_end(args);
}
