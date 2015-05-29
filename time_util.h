#ifndef TIME_UTIL_H
#define TIME_UTIL_H

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

typedef enum {SEC_PREC, MSEC_PREC, USEC_PREC} TIME_PREC;

char* sprint_exact_time_sep(char *buf, struct timeval t, char sep, TIME_PREC precision);
char* sprint_time_us_prec(char *buf, struct timeval t);
char* sprint_time_ms_prec(char *buf, struct timeval t);
char* sprint_time_sec_prec(char *buf, struct timeval t);

char* sprint_readable_time_now(char *buf);
struct timeval sprint_readable_time_diff(char *buf, struct timeval oldest, struct timeval newest);
struct timeval sprint_readable_time_now_diff(char *buf, struct timeval old_time);
long get_msecs(struct timeval tv);
long get_usecs(timeval &tv);

#define tval_pair(tval) tval.tv_sec, tval.tv_usec

/* Modified timersub macro that has defined behaviour
   also for negative differences */
# define negtimersub(a, b, result)									\
	do {															\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;				\
		(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			\
		if ((result)->tv_sec > 0) {									\
			if ((result)->tv_usec < 0) {							\
				--(result)->tv_sec;									\
				(result)->tv_usec += 1000000;						\
			}														\
		} else if ((result)->tv_sec < 0) {							\
			if ((result)->tv_usec > 0) {							\
				++(result)->tv_sec;									\
				(result)->tv_usec = 1000000 - (result)->tv_usec;	\
			} else { /* if (tv_usec < 0) */							\
				(result)->tv_usec *= -1;							\
			}														\
			if ((result)->tv_sec == 0)								\
				(result)->tv_usec *= -1;							\
		}															\
	} while (0)

void timevalfix(struct timeval *tv);
void timevaladd(struct timeval *to, struct timeval *val);
void timevalsub(struct timeval *to, struct timeval *val);

#endif /* TIME_UTIL_H */
