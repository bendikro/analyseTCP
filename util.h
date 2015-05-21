#ifndef UTIL_H
#define UTIL_H

#include <getopt.h>
#include <string>

#include "common.h"

class RangeManager;

std::string seq_pair_str(uint64_t start, uint64_t end);
std::string relative_seq_pair_str(RangeManager *rm, uint64_t start, uint64_t end);
bool isNumeric(const char* pszInput, int nNumberBase);
void parse_print_packets(char* optarg);
std::pair <std::string,std::string>  make_optstring(struct option long_options[]);
void print_stack(void);
std::string get_TCP_flags_str(u_char flags);

std::string getIp(const struct in_addr &ip);
std::string makeHostKey(const struct in_addr &ip, const uint16_t *port);
std::string makeConnKey(const struct in_addr &srcIp, const struct in_addr &dstIp, const uint16_t *srcPort, const uint16_t *dstPort);

/*
  Used to test if a sequence number comes after another
  These handle when the newest sequence number has wrapped
*/
inline bool before(uint32_t seq1, uint32_t seq2) {
	return (signed int) (seq1 - seq2) < 0;
}

inline bool after_or_equal(uint32_t seq1, uint32_t seq2) {
	return (signed int) (seq2 - seq1) >= 0;
}

#endif /* UTIL_H */
