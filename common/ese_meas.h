/* Heap accounting for wolfSSL allocations, and the DUT wall clock. */
#ifndef ESE_MEAS_H
#define ESE_MEAS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint32_t peak;    /* high-water mark above the window baseline */
    uint32_t total;   /* bytes requested inside the window */
    uint32_t allocs;  /* allocation calls inside the window */
    int32_t  held;    /* bytes still allocated at window end, relative to start */
} ese_heap_stats_t;

int ese_heap_install(void);
size_t ese_heap_cur(void);
void ese_heap_window_start(void);
void ese_heap_window_get(ese_heap_stats_t *s);

void ese_time_set(uint64_t epoch);
time_t ese_time(time_t *t);

#endif /* ESE_MEAS_H */
