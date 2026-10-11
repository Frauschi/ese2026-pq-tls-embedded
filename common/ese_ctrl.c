#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ese_ctrl.h"
#include "ese_platform.h"

void ese_line_init(ese_line_t *lb, int fd)
{
    lb->fd = fd;
    lb->len = 0;
}

int ese_line_read(ese_line_t *lb, char *out, size_t max)
{
    char *nl;
    size_t n;
    int got;

    for (;;) {
        nl = memchr(lb->buf, '\n', lb->len);
        if (nl != NULL) {
            n = (size_t)(nl - lb->buf);
            if (n >= max) {
                n = max - 1;
            }
            memcpy(out, lb->buf, n);
            out[n] = '\0';
            if (n > 0 && out[n - 1] == '\r') {
                out[--n] = '\0';
            }
            lb->len -= (size_t)(nl - lb->buf) + 1;
            memmove(lb->buf, nl + 1, lb->len);
            return (int)n;
        }
        if (lb->len == sizeof(lb->buf)) {
            lb->len = 0;
        }
        got = ese_sock_recv(lb->fd, lb->buf + lb->len,
                            sizeof(lb->buf) - lb->len);
        if (got <= 0) {
            return -1;
        }
        lb->len += (size_t)got;
    }
}

int ese_line_printf(int fd, const char *fmt, ...)
{
    char line[ESE_LINE_MAX];
    va_list ap;
    int n;
    int off = 0;
    int ret;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof(line) - 1) {
        return -1;
    }
    line[n++] = '\n';
    while (off < n) {
        ret = ese_sock_send(fd, line + off, (size_t)(n - off));
        if (ret <= 0) {
            return -1;
        }
        off += ret;
    }
    return 0;
}

int ese_line_split(char *line, char **tok, int max)
{
    int n = 0;
    char *p = line;

    while (*p != '\0' && n < max) {
        while (*p == ' ') {
            *p++ = '\0';
        }
        if (*p == '\0') {
            break;
        }
        tok[n++] = p;
        while (*p != '\0' && *p != ' ') {
            p++;
        }
    }
    return n;
}
