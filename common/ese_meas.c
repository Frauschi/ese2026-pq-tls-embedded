#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/memory.h>

#include "ese_meas.h"
#include "ese_platform.h"
#include "ese_trace.h"

/* 16 bytes keeps the user pointer aligned for any type on every target. */
#define HDR 16

static size_t cur;
static size_t peak;
static size_t base;
static size_t total;
static uint32_t count;

static void account_add(size_t sz)
{
    cur += sz;
    total += sz;
    count++;
    if (cur > peak) {
        peak = cur;
    }
}

static void *ese_malloc(size_t sz)
{
    unsigned char *p = malloc(sz + HDR);

    if (p == NULL) {
        return NULL;
    }
    memcpy(p, &sz, sizeof(sz));
    account_add(sz);
    ese_trace_heap(ESE_TRACE_ALLOC, sz, cur);
    return p + HDR;
}

static void ese_free(void *ptr)
{
    unsigned char *p = ptr;
    size_t sz;

    if (p == NULL) {
        return;
    }
    p -= HDR;
    memcpy(&sz, p, sizeof(sz));
    cur -= sz;
    ese_trace_heap(ESE_TRACE_FREE, sz, cur);
    free(p);
}

static void *ese_realloc(void *ptr, size_t sz)
{
    unsigned char *p = ptr;
    size_t old = 0;

    if (p == NULL) {
        return ese_malloc(sz);
    }
    p -= HDR;
    memcpy(&old, p, sizeof(old));
    p = realloc(p, sz + HDR);
    if (p == NULL) {
        return NULL;
    }
    memcpy(p, &sz, sizeof(sz));
    cur -= old;
    account_add(sz);
    ese_trace_heap(ESE_TRACE_REALLOC, sz, cur);
    return p + HDR;
}

int ese_heap_install(void)
{
    return wolfSSL_SetAllocators(ese_malloc, ese_free, ese_realloc);
}

size_t ese_heap_cur(void)
{
    return cur;
}

void ese_heap_window_start(void)
{
    base = cur;
    peak = cur;
    total = 0;
    count = 0;
}

void ese_heap_window_get(ese_heap_stats_t *s)
{
    s->peak = (uint32_t)(peak - base);
    s->total = (uint32_t)total;
    s->allocs = count;
    s->held = (int32_t)(cur - base);
}

static uint64_t epoch_base;
static uint64_t epoch_ns_base;

void ese_time_set(uint64_t epoch)
{
    epoch_base = epoch;
    epoch_ns_base = ese_now_ns();
}

time_t ese_time(time_t *t)
{
    time_t now = (time_t)(epoch_base +
                          (ese_now_ns() - epoch_ns_base) / 1000000000ULL);

    if (t != NULL) {
        *t = now;
    }
    return now;
}
