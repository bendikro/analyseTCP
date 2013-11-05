#include "time_util.h"

char* sprint_exact_time_sep(char *buf, struct timeval t, char sep, int micro_precision) {
	struct tm *tm_sec = gmtime(&t.tv_sec);
	char format[20];
	sprintf(format, "%%H%c%%M%c%%S", sep, sep);
	strftime(buf, 50, format, tm_sec);
	sprintf(format, "%c%%%dld", sep, micro_precision);

	int limit = 0;
	while (micro_precision--)
		limit = limit * 10 + 9;
	// Now remove digit to get the desired precission
	while (t.tv_usec > limit)
		t.tv_usec /= 10;
	sprintf(buf + strlen(buf), format, t.tv_usec);
	return buf;
}

char* sprint_exact_time_micro_prec(char *buf, struct timeval t, int micro_precision) {
	return sprint_exact_time_sep(buf, t, ':', micro_precision);
}

char* sprint_exact_time(char *buf, struct timeval t) {
	return sprint_exact_time_sep(buf, t, ':', 3);
}

struct timeval sprint_readable_time_diff(char *buf, struct timeval oldest, struct timeval newest) {
	struct timeval elapsed;
	timersub(&newest, &oldest, &elapsed);
	sprint_exact_time(buf, elapsed);
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
	sprint_exact_time(buf, now);
	return buf;
}

int get_miliseconds(struct timeval tv) {
	return tv.tv_sec * 1000 + tv.tv_usec/1000;
}
