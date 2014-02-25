#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

char* sprint_exact_time_sep(char *buf, struct timeval t, char sep, int micro_precision);
char* sprint_exact_time_micro_prec(char *buf, struct timeval t, int micro_precision);
char* sprint_exact_time(char *buf, struct timeval t);

char* sprint_readable_time_now(char *buf);
struct timeval sprint_readable_time_diff(char *buf, struct timeval oldest, struct timeval newest);
struct timeval sprint_readable_time_now_diff(char *buf, struct timeval old_time);
int get_miliseconds(struct timeval tv);

/* Modified timersub macro that has defined behaviour
   also for negative differences */
# define negtimersub(a, b, result)									\
	do {															\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;				\
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			\
		if ( (result)->tv_sec > 0) {								\
			if ((result)->tv_usec < 0) {							\
				--(result)->tv_sec;									\
				(result)->tv_usec += 1000000;						\
			}														\
		} else if ( (result)->tv_sec < 0 ) {						\
			if ((result)->tv_usec > 0) {							\
				++(result)->tv_sec;									\
				(result)->tv_usec = 1000000 - (result)->tv_usec;	\
			} else { /* if (tv_usec < 0) */							\
				(result)->tv_usec *= -1;							\
			}														\
			if((result)->tv_sec == 0 )								\
				(result)->tv_usec *= -1;							\
		}															\
	} while (0)
