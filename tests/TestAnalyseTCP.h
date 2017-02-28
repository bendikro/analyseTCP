#include <cxxtest/TestSuite.h>
#include "../Connection.h"

#define UINT_MAX (std::numeric_limits<ulong>::max())

class TestSuite : public CxxTest::TestSuite
{
public:
	void testAddition(void) {
		uint16_t port = 2000;
		in_addr src_ip;
		inet_pton(AF_INET, "192.0.2.33", &(src_ip));
		Connection *conn = new Connection(src_ip, &port, src_ip, &port, 0);
		test(conn);

		TS_ASSERT( 1 + 1 > 1 );
		TS_ASSERT_EQUALS( 1 + 1, 2 );
	}

	void test(Connection *conn) {
		uint32_t first_seq = 1000;
		uint32_t seq = 2000;
		ulong lastLargestEndSeq = 1999;
		uint32_t largestSeqAbsolute = 999;

		// TEST 1
		printf("\n\nTEST1:\n");
		printf("SEQ 1: %llu\n", getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));

		// TEST 2
		first_seq = 4294967000;
		seq = UINT_MAX -50;
		lastLargestEndSeq = UINT_MAX +100;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST2:\n");
		//printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("SEQ 2: %llu\n", getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));

		//lastLargestSeqAbsolute

		// TEST 3
		first_seq = 4294967000;
		seq = UINT_MAX + 20;
		lastLargestEndSeq = 10;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST3:\n");
		printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("SEQ 3: %llu\n", getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));

		// TEST 4
		first_seq = 4294967000;
		seq = UINT_MAX + 1;
		lastLargestEndSeq = 294;
		largestSeqAbsolute = first_seq + lastLargestEndSeq;
		printf("\n\nTEST4:\n");
		printf("seq: %u\n", seq);
		printf("first_seq: %u\n", first_seq);
		printf("largestSeqAbsolute: %u\n", largestSeqAbsolute);
		printf("SEQ 4: %llu\n", getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));

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
			printf("SEQ %d: %llu\n", i + 5, getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));
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
		printf("SEQ %d: %llu\n", i + 5, getRelativeSequenceNumber(seq, first_seq, lastLargestEndSeq, largestSeqAbsolute, conn));

		exit(0);
}
};
