#include "color_print.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int disable_colors = 0;

char *colored(int fg_color, char *buf, const char *str) {
	buf[0] = 0;

	if (fg_color != NO_COLOR && !disable_colors) {
		sprintf(buf, "%c[%d;%dm", 0x1B, 1, fg_color + 30);
	}
	strcat(buf, str);
	if (fg_color != NO_COLOR && !disable_colors) {
		char tmp[10];
		sprintf(tmp, "%c[%dm", 0x1B, RESET);
		strcat(buf, tmp);
	}
	return buf;
}


void colored_printf(int fg_color, const char *format, ...) {
	uint max_size = 1000;
	char *buf = static_cast<char*>(malloc(max_size));
	if (buf == NULL) {
		printf("Failed to allocate memory (colored_printf)!\n");
		return;
	}
	va_list ap;
	va_start(ap, format);
	vsprintf(buf, format, ap);
	va_end(ap);

	// Add color
	if (fg_color != NO_COLOR && !disable_colors) {
		char *tmp = static_cast<char*>(malloc(strlen(buf) + 30));
		if (tmp == NULL) {
			printf("Failed to allocate memory (colored_printf)!\n");
			return;
		}
		strcpy(tmp, buf);
		colored(fg_color, tmp, buf);
		strcpy(buf, tmp);
		free(tmp);
	}
	if (strlen(buf) > max_size) {
		char buf2[100];
		colored(RED, buf2, "WARNING! length of string is greater than the buffer length!!\n");
		fprintf(stderr, "%s", buf2);
	}

	printf("%s", buf);
	free(buf);
}


char* colored_sprintf(int fg_color, char *str, char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vsprintf(str, format, ap);
	va_end(ap);

	// Add color
	if (fg_color != NO_COLOR && !disable_colors) {
		char *tmp = static_cast<char*>(malloc(strlen(str) + 30));
		if (tmp == NULL) {
			printf("Failed to allocate memory (colored_sprintf)!\n");
			return 0;
		}
		strcpy(tmp, str);
		colored(fg_color, tmp, str);
		strcpy(str, tmp);
		free(tmp);
	}
	return str;
}

void printf_c(const char *fmt, ...) {
	va_list argp;
	va_start(argp, fmt);
	vfprintf(stderr, fmt, argp);
	va_end(argp);
	printf(KNRM); // Terminate color after this printf
}
