#ifndef UTIL_H
#define UTIL_H

#define SSTR( x ) dynamic_cast< std::ostringstream & >( \
		( std::ostringstream() << std::dec << x ) ).str()

class RangeManager;

string seq_pair_str(uint64_t start, uint64_t end);
string relative_seq_pair_str(RangeManager *rm, uint64_t start, uint64_t end);

#endif /* UTIL_H */
