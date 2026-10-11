/* POSIX implementation of ese_platform.h (Linux DUT and the host helper). */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ese_platform.h"

#define STACK_SIZE (128 * 1024)
#define STACK_PAINT 0xA5
#define STACK_PAINT_WORD (~(uintptr_t)0 / 0xFF * STACK_PAINT)

uint64_t ese_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void ese_sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

    nanosleep(&ts, NULL);
}

/* A link that dies silently must fail the connection, not block the run forever. */
static void set_nodelay(int fd)
{
    struct timeval tv = { 600, 0 };
    int one = 1;

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int ese_sock_connect(const char *ip, uint16_t port)
{
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    set_nodelay(fd);
    return fd;
}

int ese_sock_listen(uint16_t port)
{
    struct sockaddr_in sa;
    const char *bind_ip = getenv("ESE_BIND_IP");
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind_ip != NULL && inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ese_sock_accept(int lfd, int timeout_ms)
{
    struct pollfd p = { lfd, POLLIN, 0 };
    int fd;

    if (timeout_ms > 0 && poll(&p, 1, timeout_ms) <= 0) {
        return -1;
    }
    do {
        fd = accept(lfd, NULL, NULL);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
        set_nodelay(fd);
    }
    return fd;
}

int ese_sock_send(int fd, const void *buf, size_t len)
{
    ssize_t n;

    do {
        n = send(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);
    return (int)n;
}

int ese_sock_recv(int fd, void *buf, size_t len)
{
    ssize_t n;

    do {
        n = recv(fd, buf, len, 0);
    } while (n < 0 && errno == EINTR);
    return (int)n;
}

void ese_sock_close(int fd)
{
    close(fd);
}

typedef struct {
    void (*fn)(void *);
    void *arg;
    unsigned char *stack;
    size_t used;
} thread_arg_t;

/* Depth below this frame, scanned before glibc's thread-exit code dirties the stack. */
static void *thread_main(void *p)
{
    thread_arg_t *t = (thread_arg_t *)p;
    unsigned char *entry = __builtin_frame_address(0);
    volatile uintptr_t *w = (volatile uintptr_t *)t->stack;
    volatile uintptr_t *top = (volatile uintptr_t *)((uintptr_t)(entry - 256) &
                                                    ~(sizeof(uintptr_t) - 1));
    volatile unsigned char *low;

    /* glibc's start path already dirtied the area below this frame. */
    while (w < top) {
        *w++ = STACK_PAINT_WORD;
    }
    t->fn(t->arg);
    w = (volatile uintptr_t *)t->stack;
    while (w < top && *w == STACK_PAINT_WORD) {
        w++;
    }
    low = (volatile unsigned char *)w;
    while (low < entry && *low == STACK_PAINT) {
        low++;
    }
    t->used = (size_t)(entry - (unsigned char *)low);
    return NULL;
}

int ese_run_measured(void (*fn)(void *), void *arg, size_t *stack_used)
{
    static unsigned char *stack;
    thread_arg_t t = { fn, arg, NULL, 0 };
    pthread_attr_t attr;
    pthread_t th;
    int ret;

    if (stack == NULL) {
        stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
        if (stack == MAP_FAILED) {
            stack = NULL;
            return -1;
        }
    }
    t.stack = stack;
    pthread_attr_init(&attr);
    pthread_attr_setstack(&attr, stack, STACK_SIZE);
    ret = pthread_create(&th, &attr, thread_main, &t);
    pthread_attr_destroy(&attr);
    if (ret != 0) {
        return -1;
    }
    pthread_join(th, NULL);
    *stack_used = t.used;
    return 0;
}

const char *ese_platform_name(void)
{
#if defined(ESE_PLATFORM_NAME)
    return ESE_PLATFORM_NAME;
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

uint32_t ese_cpu_hz(void)
{
    unsigned long khz = 0;
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
                    "r");

    if (f != NULL) {
        if (fscanf(f, "%lu", &khz) != 1) {
            khz = 0;
        }
        fclose(f);
    }
    return (uint32_t)(khz * 1000UL);
}

void ese_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
