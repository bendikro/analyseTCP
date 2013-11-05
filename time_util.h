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
