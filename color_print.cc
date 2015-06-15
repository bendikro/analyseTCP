#include "color_print.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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

char* _colored_sprintf(uint32_t max_size, char *buf, int fg_color, const char *format, va_list args) {
	vsprintf(buf, format, args);

	// Add color
	if (fg_color != NO_COLOR && !disable_colors) {
		char *tmp = (char*) malloc(strlen(buf) + 30);
		if (tmp == NULL) {
			printf("Failed to allocate memory (colored_sprintf)!\n");
			return 0;
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
	return buf;
}

void _colored_printf(FILE *stream, uint32_t max_size, int fg_color, const char *format, va_list args) {
	char *buf = (char*) malloc(max_size);
	if (buf == NULL) {
		printf("Failed to allocate memory (colored_printf)!\n");
		return;
	}
	_colored_sprintf(max_size, buf, fg_color, format, args);
	fprintf(stream, "%s", buf);
	free(buf);
}

void colored_fprintf(FILE *stream, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_printf(stream, 1000, fg_color, format, args);
	va_end(args);
}
void colored_printf(int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_printf(stdout, 1000, fg_color, format, args);
	va_end(args);
}

char* colored_sprintf(uint32_t max_size, char *buf, int fg_color, const char *format, ...) {
	va_list args;
	va_start(args, format);
	_colored_sprintf(max_size, buf, fg_color, format, args);
	va_end(args);
	return buf;
}
