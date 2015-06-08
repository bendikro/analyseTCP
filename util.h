#ifndef UTIL_H
#define UTIL_H

#include <getopt.h>
#include <string>

#include "common.h"

class RangeManager;

bool isNumeric(const char* pszInput, int nNumberBase);
void parse_print_packets(char* optarg);
std::pair <std::string,std::string>  make_optstring(option long_options[]);
void print_stack(void);
std::string get_TCP_flags_str(u_char flags);

std::string ipToStr(const in_addr &ip);
std::string makeHostKey(const in_addr &ip, const uint16_t *port);
std::string makeConnKey(const in_addr &srcIp, const in_addr &dstIp, const uint16_t *srcPort, const uint16_t *dstPort);

#ifdef __linux__
void print_stack();
#endif

// Used to avoid variable unused compiler warnings where necessary
#define UNUSED(x) (void)(x)

template<typename ... Args>
string strfmt(const string& format, Args ... args) {
	size_t size = snprintf(nullptr, 0, format.c_str(), args...);
	std::string buf;
    buf.reserve(size + 1);
    buf.resize(size);
    snprintf(&buf[0], size + 1, format.c_str(), args...);
    return buf;
}

/*
  Used to test if a sequence number comes after another
  These handle when the newest sequence number has wrapped
*/
inline bool before(seq32_t seq1, seq32_t seq2) {
	return (signed int) (seq1 - seq2) < 0;
}

inline bool after_or_equal(seq32_t seq1, seq32_t seq2) {
	return (signed int) (seq2 - seq1) >= 0;
}

#endif /* UTIL_H */
