/**************************************
  Stuff for coloring output to terminal
***************************************/

#ifndef COLOR_PRINT_H
#define COLOR_PRINT_H

#include <stdio.h>
#include <stdint.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

extern int disable_colors;

#ifdef __cplusplus
extern "C" {
#endif

char *colored(int fg_color, char *buf, const char *str);
void colored_printf(int fg_color, const char *format, ...);
void colored_fprintf(FILE *stream, int fg_color, const char *format, ...);
char* colored_sprintf(uint32_t max_size, char *buf, int fg_color, const char *format, ...);

#ifdef __cplusplus
}
#endif

#define RESET 0
#define BRIGHT 1
#define DIM 2
#define UNDERLINE 3
#define BLINK 4
#define REVERSE 7
#define HIDDEN 8

#define NO_COLOR -1
#define BLACK 0
#define RED 1
#define GREEN 2
#define YELLOW 3
#define BLUE 4
#define MAGENTA 5
#define CYAN 6
#define WHITE 7

#endif /* COLOR_PRINT_H */
