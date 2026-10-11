/* Line-based control channel between host and DUT. */
#ifndef ESE_CTRL_H
#define ESE_CTRL_H

#include <stddef.h>

#define ESE_LINE_MAX 384

typedef struct {
    int fd;
    char buf[ESE_LINE_MAX];
    size_t len;
} ese_line_t;

void ese_line_init(ese_line_t *lb, int fd);
/* Returns the line length without the newline, or <0 on EOF or error. */
int ese_line_read(ese_line_t *lb, char *out, size_t max);
int ese_line_printf(int fd, const char *fmt, ...);

/* Splits a line in place on spaces; returns the number of tokens. */
int ese_line_split(char *line, char **tok, int max);

#endif /* ESE_CTRL_H */
