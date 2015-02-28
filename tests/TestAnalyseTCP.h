#include <cxxtest/TestSuite.h>
#include "../Dump.h"

#define UINT_MAX (std::numeric_limits<ulong>::max())

class TestSuite : public CxxTest::TestSuite
{
public:
	void testAddition(void) {
		Dump *senderDump = new Dump("", "", "", "", "", "");
		test(senderDump);

		TS_ASSERT( 1 + 1 > 1 );
		TS_ASSERT_EQUALS( 1 + 1, 2 );
	}

	void test(Dump *d) {
		uint32_t first_seq = 1000;
		uint32_t seq = 2000;
		ulong lastLargestEndSeq = 1999;
		uint32_t largestSeqAbsolute = 999;

		// TEST 1
		printf("\n\nTEST1:\n");
		printf("SEQ 1: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));

		// TEST 2
		first_seq = 4294967000;
		seq = UINT_MAX -50;
		lastLargestEndSeq = UINT_MAX +100;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST2:\n");
		//printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("SEQ 2: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));

		//lastLargestSeqAbsolute

		// TEST 3
		first_seq = 4294967000;
		seq = UINT_MAX + 20;
		lastLargestEndSeq = 10;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST3:\n");
		printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("SEQ 3: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));

		// TEST 4
		first_seq = 4294967000;
		seq = UINT_MAX + 1;
		lastLargestEndSeq = 294;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST4:\n");
		printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("largestSeqAbsolute: %u\n", largestSeqAbsolute);
		printf("SEQ 4: %lu\n", d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));

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
			printf("SEQ %d: %lu\n", i + 5, d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));
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
		printf("SEQ %d: %lu\n", i + 5, d->get_relative_sequence_number(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, NULL));

		exit(1);
}
};
