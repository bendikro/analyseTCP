#include "color_print.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

int disable_colors = 0;

int _colored(int fg_color, uint32_t max_size, char *buf, const char *str) {
	int n;
	buf[0] = 0;
	if (fg_color != NO_COLOR && !disable_colors) {
		n = snprintf(buf, max_size, "%c[%d;5;%dm%s%c[m", 0x1B, 38, fg_color, str, 0x1B);
	}
	else {
		n = snprintf(buf, max_size, "%s", str);
	}
	return n;
}

char *colored(int fg_color, uint32_t max_size, char *buf, const char *str) {
	int n = _colored(fg_color, max_size, buf, str);
	if (n >= max_size) {
		char tmp_pbuf[100], tmp_pbuf2[100];
		snprintf(tmp_pbuf, sizeof(tmp_pbuf), "colored: WARNING! length of string is greater than max_size(%u)!\n", max_size);
		_colored(RED, sizeof(tmp_pbuf2), tmp_pbuf2, tmp_pbuf);
		fprintf(stderr, "%s", tmp_pbuf2);
	}
	return buf;
}


char* _colored_sprintf(char *buf, uint32_t max_size, int fg_color, const char *format, va_list args) {
	int n = vsnprintf(buf, max_size, format, args);
	if (n >= max_size) {
		char tmp_pbuf[100];
		colored(RED, sizeof(tmp_pbuf), tmp_pbuf, "WARNING! length of string is greater than the buffer length!!\n");
		fprintf(stderr, "%s", tmp_pbuf);
	}

	// Add color
	if (n < max_size &&  fg_color != NO_COLOR && !disable_colors) {
		size_t tmp_size = strlen(buf) + 30;
		char *tmp = (char*) malloc(tmp_size);
		if (tmp == NULL) {
			fprintf(stderr, "Failed to allocate memory (colored_sprintf)!\n");
			return 0;
		}
		strcpy(tmp, buf);
		n = _colored(fg_color, tmp_size, tmp, buf);
		strcpy(buf, tmp);
		free(tmp);
	}
	return buf;
}

void _colored_fprintf(FILE *stream, uint32_t max_size, int fg_color, const char *format, va_list args) {
	char *buf = (char*) malloc(max_size);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate memory (_colored_printf)!\n");
		return;
	}
	_colored_sprintf(buf, max_size, fg_color, format, args);
	fprintf(stream, "%s", buf);
	free(buf);
}

void colored_fprintf(FILE *stream, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_fprintf(stream, 1000, fg_color, format, args);
	va_end(args);
}
void colored_printf(int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_fprintf(stdout, 1000, fg_color, format, args);
	va_end(args);
}

char* colored_sprintf(uint32_t max_size, char *buf, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_sprintf(buf, max_size, fg_color, format, args);
	va_end(args);
	return buf;
}
