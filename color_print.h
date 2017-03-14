/**************************************
  Stuff for coloring output to terminal
***************************************/

#ifndef COLOR_PRINT_H
#define COLOR_PRINT_H

#include <stdio.h>
#include <stdint.h>

extern int disable_colors;

#ifdef __cplusplus
extern "C" {
#endif

void _colored_fprintf(FILE *stream, uint32_t max_size, int fg_color, const char *format, va_list args);
char *colored(int fg_color, uint32_t max_size, char *buf, const char *str);
void colored_printf(int fg_color, const char *format, ...);
void colored_fprintf(FILE *stream, int fg_color, const char *format, ...);
char* colored_sprintf(uint32_t max_size, char *buf, int fg_color, const char *format, ...);

#ifdef __cplusplus
}
#endif

#define NO_COLOR  -1
#define BLACK      0
#define RED        1
#define GREEN      2
#define YELLOW     3
#define BLUE       4
#define MAGENTA    5
#define CYAN       6
#define WHITE      7

#define RED2     196
#define GREEN2    34
#define YELLOW2   11
#define BLUE2     27
#define WHITE2    15

#define GREEN3    40
#define BLUE3     45

#endif /* COLOR_PRINT_H */
