#include "common.h"
#include <stdarg.h>
#include <string.h>

/* Initialize global options */
bool GlobOpts::aggregate                              = false;
bool GlobOpts::aggOnly                                = false;
bool GlobOpts::withRecv                               = false;
bool GlobOpts::withLoss                               = false;
bool GlobOpts::withCDF                                = false;
bool GlobOpts::transport                              = false;
bool GlobOpts::genAckLatencyFiles                     = false;
bool GlobOpts::genPerPacketStats                      = false;
bool GlobOpts::genPerSegmentStats                     = false;
bool GlobOpts::withThroughput                         = false;
string GlobOpts::prefix                               = "";
string GlobOpts::RFiles_dir                           = "";
int GlobOpts::debugLevel                              = 1;
bool GlobOpts::debugSender                            = true;
bool GlobOpts::debugReceiver                          = true;
uint64_t GlobOpts::lossAggrMs                         = 1000;
uint64_t GlobOpts::throughputAggrMs                   = 1000;
bool GlobOpts::relative_seq                           = false;
bool GlobOpts::print_packets                          = false;
string GlobOpts::sendNatIP                            = "";
string GlobOpts::recvNatIP                            = "";
bool GlobOpts::connDetails                            = false;
bool GlobOpts::writeConnDetails                       = false;
int GlobOpts::verbose                                 = 1;
bool GlobOpts::validate_ranges                        = true;
int GlobOpts::max_retrans_stats                       = 6;
string GlobOpts::percentiles                          = "";
int GlobOpts::analyse_start                           = 0;
int GlobOpts::analyse_end                             = 0;
long GlobOpts::analyse_duration                       = 0;
string GlobOpts::sojourn_time_file                    = "";
bool GlobOpts::oneway_delay_variance                  = false;
bool GlobOpts::look_for_get_request                   = false;
bool GlobOpts::conn_key_debug                         = false;

	/* Debug warning prints */
bool GlobOpts::print_payload_mismatch_warn            = true;
bool GlobOpts::print_timestamp_mismatch_warn          = true;
bool GlobOpts::print_missing_byterange_warn           = true;
bool GlobOpts::print_pkt_header_caplen_truncated_warn = true; // Entire TCP header not captured
int GlobOpts::pkt_header_caplen_truncated_count       = 0;

vector <pair<uint64_t, uint64_t> > GlobOpts::print_packets_pairs;
in_addr GlobOpts::sendNatAddr;
in_addr GlobOpts::recvNatAddr;

bool operator==(const timeval& lhs, const timeval& rhs) {
	return lhs.tv_sec == rhs.tv_sec && lhs.tv_usec == rhs.tv_usec;
}

void print_with_file_and_linenum(string type, string file, int linenum) {
	cerr << type << " at file: " << file << " Line: " << linenum  << endl;
}

void warn_with_file_and_linenum(string file, int linenum) {
	print_with_file_and_linenum("Warning", file, linenum);
}

void exit_with_file_and_linenum(int exit_code, string file, int linenum) {
	print_with_file_and_linenum("Error", file, linenum);
	exit(exit_code);
}

bool endsWith(const string& s, const string& suffix) {
	return s.rfind(suffix) == (s.size()-suffix.size());
}

string debug_type_str(enum debug_type t) {
	switch(t) {
	case DSENDER:   return "sender";
	case DRECEIVER: return "receiver";
	default: return "Invalid debug type";
    }
}

bool check_debug_level(enum debug_type type, int level) {
	switch(type) {
	case DSENDER:   return DEBUGL_SENDER(level);
	case DRECEIVER: return DEBUGL_RECEIVER(level);
	default: return false;
    }
}


#define call_with_va_args(func_call) va_list args; va_start(args, format); func_call; va_end(args);


/***************************
 *  Debug print functions
 ****************************/
void _dclfprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, va_list args) {
	if (type == DSENDER && !DEBUGL_SENDER(debug_level))
		return;
	else if (type == DRECEIVER && !DEBUGL_RECEIVER(debug_level))
		return;

	size_t fmt_len = strlen(format) + PREFIX_LEN;
	char *d_format = (char*) malloc(fmt_len);
	snprintf(d_format, fmt_len, DEBUG_PREFIX_FMT, debug_level);
	strcat(d_format, format);
	_colored_fprintf(stream, PRINT_MAX_BUFFER, fg_color, d_format, args);
}

/* Colored printf */
void dclprintf(enum debug_type type, int debug_level, int fg_color, const char *format, ...) {
	call_with_va_args(_dclfprintf(stdout, type, debug_level, fg_color, format, args));
}

/* Colored fprintf */
void dclfprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, ...) {
	call_with_va_args(_dclfprintf(stream, type, debug_level, fg_color, format, args));
}

/* printf */
void dprintf(enum debug_type type, int debug_level, const char *format, ...) {
	call_with_va_args(_dclfprintf(stdout, type, debug_level, NO_COLOR, format, args));
}

/* fprintf */
void dfprintf(FILE *stream, enum debug_type type, int debug_level, const char *format, ...) {
	call_with_va_args(_dclfprintf(stream, type, debug_level, NO_COLOR, format, args));
}

/***************************
 *  Verbosity print functions
 ****************************/
void _vbclfprintf(FILE *stream, int verbose_level, int fg_color, const char *format, va_list args) {
	if (GlobOpts::verbose < verbose_level) {
		return;
	}
	_colored_fprintf(stream, PRINT_MAX_BUFFER, fg_color, format, args);
}

/* Colored fprintf */
void vbclfprintf(FILE *stream, int verbose_level, int fg_color, const char *format, ...) {
	call_with_va_args(_vbclfprintf(stream, verbose_level, fg_color, format, args));
}

/* Colored printf */
void vbclprintf(int verbose_level, int fg_color, const char *format, ...) {
	call_with_va_args(_vbclfprintf(stdout, verbose_level, fg_color, format, args));
}

/* fprintf */
void vbfprintf(FILE *stream, int verbose_level, const char *format, ...) {
	call_with_va_args(_vbclfprintf(stream, verbose_level, NO_COLOR, format, args));
}

/* printf */
void vbprintf(int verbose_level, const char *format, ...) {
	call_with_va_args(_vbclfprintf(stdout, verbose_level, NO_COLOR, format, args));
}
