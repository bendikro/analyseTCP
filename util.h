#ifndef UTIL_H
#define UTIL_H

#define SSTR( x ) dynamic_cast< std::ostringstream & >( \
		( std::ostringstream() << std::dec << x ) ).str()

#include <getopt.h>

class RangeManager;

string seq_pair_str(uint64_t start, uint64_t end);
string relative_seq_pair_str(RangeManager *rm, uint64_t start, uint64_t end);
bool isNumeric(const char* pszInput, int nNumberBase);
void parse_print_packets(char* optarg);
pair <string,string>  make_optstring(struct option long_options[]);

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
