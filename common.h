#ifndef COMMON_H
#define COMMON_H

/*
  As uint64_t is defined as unsigned long on Linux (gcc/clang) and
  unsigned long long on OSX. Printing such values is troublesome as
  linux requires %lu, and OSX %llu. Therefore we use ullint_t and
  llint_t for variables that must be at least 64 bits, which can be
  printed on all platforms with %llu.

  On Linux (with clang), include the following two defines to test if
  the compiler will give warnings when compiled on OSX where
  (u)int64_t is (unsigned) long long.

#define uint64_t unsigned long long
#define int64_t long long
*/
// Following types are at least 64 bit
#define ullint_t unsigned long long
#define llint_t long long

#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cassert>
#include <ctype.h>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <pcap.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <map>

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef OS_FREEBSD
#include <sys/socket.h>
#endif

#include <netinet/if_ether.h> // Must come after <sys/socket.h> on FreeBSD

#ifdef HAVE_STD_MEMORY_HEADER
  #include <memory>
#elif defined(HAVE_TR1_MEMORY_HEADER)
  #include <tr1/memory>
#else
  #error no C++ memory header defined, perhaps boost?
#endif
#ifdef SHARED_PTR_TR1_NAMESPACE
  #define SPNS std::tr1
#else
  #define SPNS std
#endif

using namespace std;

#include "color_print.h"

// Max size of the char buffer used for verbose/debug print functions
#define PRINT_MAX_BUFFER 1000

#define safe_div(x, y) ((y) != 0 ? ((double) (x)) / (y) : 0.0)

enum relative_seq_type {RELSEQ_NONE, RELSEQ_SEND_OUT, RELSEQ_SEND_ACK, RELSEQ_RECV_INN, RELSEQ_SOJ_SEQ};

enum sent_type {ST_NONE, ST_PKT, ST_RTR, ST_PURE_ACK, ST_RST};

/* Compare two timevals */
bool operator==(const timeval& lhs, const timeval& rhs);

/* Class to keep global options */
class GlobOpts {
private:

public:
	static bool aggregate;
	static bool aggOnly;
	static bool aggInfo;
	static bool transport;
	static bool withRecv;
	static bool withLoss;
	static uint64_t lossAggrMs;
	static bool withThroughput;
	static uint64_t throughputAggrMs;
	static bool withCDF;
	static bool relative_seq;
	static bool print_packets;
	static vector <pair<uint64_t, uint64_t> > print_packets_pairs;
	static string sendNatIP;
	static string recvNatIP;
	static in_addr sendNatAddr;
	static in_addr recvNatAddr;
	static bool genAckLatencyFiles;
	static bool genPerPacketStats;
	static bool genPerSegmentStats;
	static string prefix;
	static string RFiles_dir;
	static bool connDetails;
	static bool writeConnDetails;
	static int verbose;
	static bool validate_ranges;
	static int max_retrans_stats;
	static string percentiles;
	static int analyse_start;
	static int analyse_end;
	static long analyse_duration;
	static string sojourn_time_file;
	static bool oneway_delay_variance;
	static bool look_for_get_request;
	/* Debug warning prints */
	static int  debugLevel;
	static bool debugSender;
	static bool debugReceiver;
	static bool print_payload_mismatch_warn;
	static bool print_timestamp_mismatch_warn;
	static bool print_missing_byterange_warn;
	static bool print_pkt_header_caplen_truncated_warn;
	/* Debug test variables */
	static bool conn_key_debug;
	static int pkt_header_caplen_truncated_count;
};

#define DEBUGL(level) (GlobOpts::debugLevel >= level)
#define DEBUGL_SENDER(level) (GlobOpts::debugSender && GlobOpts::debugLevel >= level)
#define DEBUGL_RECEIVER(level) (GlobOpts::debugReceiver && GlobOpts::debugLevel >= level)


bool endsWith(const string& s, const string& suffix);
string file_and_linenum();
void exit_with_file_and_linenum(int exit_code, string file, int linenum);
void warn_with_file_and_linenum(string file, int linenum);

/* Debug/Verbose printing */

enum debug_type {DSENDER, DRECEIVER};

string debug_type_str(enum debug_type t);
bool check_debug_level(enum debug_type type, int debugLevel);

#define DEBUG_PREFIX_FMT "[DEBUG %d] "
#define PREFIX_LEN 20

#define COLOR_FATAL RED
#define COLOR_ERROR RED
#define COLOR_WARN YELLOW2
#define COLOR_NOTICE YELLOW2
#define COLOR_INFO GREEN2

void dclprintf(enum debug_type type, int debug_level, int fg_color, const char *format, ...);
void dclfprintf(FILE *stream, enum debug_type type, int debug_level, int fg_color, const char *format, ...);
void dprintf(enum debug_type type, int debug_level, const char *format, ...);
void dfprintf(FILE *stream, enum debug_type type, int debug_level, const char *format, ...);

void vbclfprintf(FILE *stream, int verbose_level, int fg_color, const char *format, ...);
void vbclprintf(int verbose_level, int fg_color, const char *format, ...);
void vbfprintf(FILE *stream, int verbose_level, const char *format, ...);
void vbprintf(int verbose_level, const char *format, ...);
/* END printing */

#endif /* COMMON_H */
