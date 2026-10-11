/* Zephyr implementation of ese_platform.h. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/printk.h>

#include "ese_platform.h"

#define STACK_PAINT 0xA5
#define STACK_PAINT_WORD (~(uintptr_t)0 / 0xFF * STACK_PAINT)

K_THREAD_STACK_DEFINE(meas_stack, CONFIG_ESE_MEAS_STACK_SIZE);
static struct k_thread meas_thread;

#ifdef CONFIG_TIMER_HAS_64BIT_CYCLE_COUNTER
static uint64_t cycles64(void)
{
    return k_cycle_get_64();
}
#else
/* k_cycle_get_32() wraps within seconds at core clock; a 1 s timer tracks the wraps. */
static struct k_spinlock cyc_lock;
static uint32_t cyc_last;
static uint64_t cyc_hi;

static uint64_t cycles64(void)
{
    k_spinlock_key_t key = k_spin_lock(&cyc_lock);
    uint32_t now = k_cycle_get_32();
    uint64_t v;

    if (now < cyc_last) {
        cyc_hi += 1ULL << 32;
    }
    cyc_last = now;
    v = cyc_hi | now;
    k_spin_unlock(&cyc_lock, key);
    return v;
}

static void cyc_tick(struct k_timer *t)
{
    ARG_UNUSED(t);
    (void)cycles64();
}

K_TIMER_DEFINE(cyc_timer, cyc_tick, NULL);

static int cyc_init(void)
{
    k_timer_start(&cyc_timer, K_SECONDS(1), K_SECONDS(1));
    return 0;
}

SYS_INIT(cyc_init, APPLICATION, 99);
#endif

uint64_t ese_now_ns(void)
{
    return k_cyc_to_ns_floor64(cycles64());
}

void ese_sleep_ms(int ms)
{
    k_msleep(ms);
}

static void set_nodelay(int fd)
{
    int one = 1;

    zsock_setsockopt(fd, NET_IPPROTO_TCP, ZSOCK_TCP_NODELAY, &one,
                     sizeof(one));
}

int ese_sock_connect(const char *ip, uint16_t port)
{
    struct net_sockaddr_in sa;
    int fd;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = NET_AF_INET;
    sa.sin_port = net_htons(port);
    if (zsock_inet_pton(NET_AF_INET, ip, &sa.sin_addr) != 1) {
        return -1;
    }
    fd = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    if (zsock_connect(fd, (struct net_sockaddr *)&sa, sizeof(sa)) != 0) {
        zsock_close(fd);
        return -1;
    }
    set_nodelay(fd);
    return fd;
}

int ese_sock_listen(uint16_t port)
{
    struct net_sockaddr_in sa;
    int one = 1;
    int fd = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TCP);

    if (fd < 0) {
        return -1;
    }
    zsock_setsockopt(fd, ZSOCK_SOL_SOCKET, ZSOCK_SO_REUSEADDR, &one,
                     sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = NET_AF_INET;
    sa.sin_port = net_htons(port);
    if (zsock_bind(fd, (struct net_sockaddr *)&sa, sizeof(sa)) != 0 ||
        zsock_listen(fd, 2) != 0) {
        zsock_close(fd);
        return -1;
    }
    return fd;
}

int ese_sock_accept(int lfd, int timeout_ms)
{
    struct zsock_pollfd p = { .fd = lfd, .events = ZSOCK_POLLIN };
    int fd;

    if (timeout_ms > 0 && zsock_poll(&p, 1, timeout_ms) <= 0) {
        return -1;
    }
    fd = zsock_accept(lfd, NULL, NULL);
    if (fd >= 0) {
        set_nodelay(fd);
    }
    return fd;
}

int ese_sock_send(int fd, const void *buf, size_t len)
{
    return (int)zsock_send(fd, buf, len, 0);
}

int ese_sock_recv(int fd, void *buf, size_t len)
{
    return (int)zsock_recv(fd, buf, len, 0);
}

void ese_sock_close(int fd)
{
    zsock_close(fd);
}

typedef struct {
    void (*fn)(void *);
    void *arg;
    size_t used;
} job_t;

/* Same method as the POSIX port: depth below the entry frame, repainted on entry. */
static void meas_entry(void *p1, void *p2, void *p3)
{
    job_t *j = p1;
    unsigned char *base = (unsigned char *)k_current_get()->stack_info.start;
    unsigned char *entry = __builtin_frame_address(0);
    volatile uintptr_t *w = (volatile uintptr_t *)base;
    volatile uintptr_t *top = (volatile uintptr_t *)((uintptr_t)(entry - 256) &
                                                    ~(sizeof(uintptr_t) - 1));
    volatile unsigned char *low;

    ARG_UNUSED(p2);
    ARG_UNUSED(p3);
    if (IS_ENABLED(CONFIG_ARCH_POSIX)) {
        /* native_sim runs threads on host stacks, not on the Zephyr buffer. */
        j->fn(j->arg);
        return;
    }
    while (w < top) {
        *w++ = STACK_PAINT_WORD;
    }
    j->fn(j->arg);
    w = (volatile uintptr_t *)base;
    while (w < top && *w == STACK_PAINT_WORD) {
        w++;
    }
    low = (volatile unsigned char *)w;
    while (low < entry && *low == STACK_PAINT) {
        low++;
    }
    j->used = (size_t)(entry - (unsigned char *)low);
}

int ese_run_measured(void (*fn)(void *), void *arg, size_t *stack_used)
{
    job_t j = { fn, arg, 0 };
    k_tid_t tid;

    tid = k_thread_create(&meas_thread, meas_stack,
                          K_THREAD_STACK_SIZEOF(meas_stack), meas_entry, &j,
                          NULL, NULL, CONFIG_ESE_MEAS_THREAD_PRIO, 0,
                          K_NO_WAIT);
    if (tid == NULL) {
        return -1;
    }
    k_thread_join(tid, K_FOREVER);
    *stack_used = j.used;
    return 0;
}

const char *ese_platform_name(void)
{
    return CONFIG_BOARD_TARGET;
}

uint32_t ese_cpu_hz(void)
{
#if DT_NODE_HAS_PROP(DT_PATH(cpus, cpu_0), clock_frequency)
    return DT_PROP(DT_PATH(cpus, cpu_0), clock_frequency);
#else
    return (uint32_t)sys_clock_hw_cycles_per_sec();
#endif
}

void ese_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintk(fmt, ap);
    va_end(ap);
}
