/* Heap-event trace with handshake markers, compiled in only for trace builds. */
#ifndef ESE_TRACE_H
#define ESE_TRACE_H

#include <stddef.h>

#define ESE_TRACE_ALLOC   0
#define ESE_TRACE_FREE    1
#define ESE_TRACE_REALLOC 2

#ifdef ESE_HEAP_TRACE

void ese_trace_init(void);
void ese_trace_arm(void);
void ese_trace_start(void);
void ese_trace_stop(void);
void ese_trace_mark(const char *label);
void ese_trace_step(const char *label, int end);
void ese_trace_heap(int kind, size_t size, size_t cur);
void ese_trace_dump(int cfd);

#else

#define ese_trace_init()             do { } while (0)
#define ese_trace_arm()              do { } while (0)
#define ese_trace_start()            do { } while (0)
#define ese_trace_stop()             do { } while (0)
#define ese_trace_mark(label)        do { (void)(label); } while (0)
#define ese_trace_step(label, end)   do { (void)(label); (void)(end); } while (0)
#define ese_trace_heap(k, s, c)      do { } while (0)

#endif /* ESE_HEAP_TRACE */

#endif /* ESE_TRACE_H */
