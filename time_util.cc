#include "time_util.h"

char* sprint_exact_time_sep(char *buf, struct timeval t, char sep, TIME_PREC precision) {
	struct tm *tm_sec = gmtime(&t.tv_sec);
	char format[20];
	sprintf(format, "%%H%c%%M%c%%S", sep, sep);
	strftime(buf, 50, format, tm_sec);

	if (precision != SEC_PREC) {
		sprintf(format, "%c%%0%dld", sep, precision * 3);
		long int time = t.tv_usec;
		switch (precision) {
		case MSEC_PREC: {
			time /= 1000;
			break;
		}
		case USEC_PREC: {
			time /= 1;
			break;
		}
		default:{}
		}
		sprintf(buf + strlen(buf), format, time);
	}
	return buf;
}

char* sprint_time_us_prec(char *buf, struct timeval t) {
	return sprint_exact_time_sep(buf, t, ':', USEC_PREC);
}

char* sprint_time_ms_prec(char *buf, struct timeval t) {
	return sprint_exact_time_sep(buf, t, ':', MSEC_PREC);
}

char* sprint_time_sec_prec(char *buf, struct timeval t) {
	return sprint_exact_time_sep(buf, t, ':', SEC_PREC);
}

struct timeval sprint_readable_time_diff(char *buf, struct timeval oldest, struct timeval newest) {
	struct timeval elapsed;
	timersub(&newest, &oldest, &elapsed);
	sprint_time_ms_prec(buf, elapsed);
	return elapsed;
}

struct timeval sprint_readable_time_now_diff(char *buf, struct timeval old_time) {
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval elapsed = sprint_readable_time_diff(buf, old_time, now);
	return elapsed;
}

char* sprint_readable_time_now(char *buf) {
	struct timeval now;
	gettimeofday(&now, NULL);
	sprint_time_ms_prec(buf, now);
	return buf;
}

int get_miliseconds(struct timeval tv) {
	return tv.tv_sec * 1000 + tv.tv_usec/1000;
}

int get_usecs(timeval &tv) {
	return tv.tv_sec * 1000000 + tv.tv_usec;
}


void timevalfix(struct timeval *tv) {
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
    }

	if (tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
    }
}

/*! Add a timeval.
    Add in \b to the time in \b val.
    @param to  result and value to add
    @param val value to add
    @see timevalsub
*/
void timevaladd(struct timeval *to, struct timeval *val) {
	to->tv_sec += val->tv_sec;
	to->tv_usec += val->tv_usec;
	timevalfix(to);
}



/*! Subtract a timeval.
    Subtract from \b to the time in \b val.  The result time can
    become negative.
    @param to  result and value from which to subtract
    @param val value to subtract
    @see timevaladd
*/
void timevalsub(struct timeval *to, struct timeval *val) {
	to->tv_sec -= val->tv_sec;
	to->tv_usec -= val->tv_usec;
	timevalfix(to);
}
