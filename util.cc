#include "RangeManager.h"
#include "util.h"

string seq_pair_str(uint64_t start, uint64_t end) {
	stringstream s;
	s << start << ", " << end;
	return s.str();
}

string relative_seq_pair_str(RangeManager *rm, uint64_t start, uint64_t end) {
	if (!GlobOpts::relative_seq) {
		start = rm->relative_seq(start);
		end = rm->relative_seq(end);
	}
	return seq_pair_str(start, end);
}
