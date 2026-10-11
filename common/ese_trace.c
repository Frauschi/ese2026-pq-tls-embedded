#include <wolfssl/wolfcrypt/settings.h>

#ifdef ESE_HEAP_TRACE

#include <inttypes.h>
#include <string.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "ese_ctrl.h"
#include "ese_meas.h"
#include "ese_platform.h"
#include "ese_trace.h"

#ifdef __ZEPHYR__
    #include <zephyr/devicetree.h>
    #include <zephyr/linker/section_tags.h>
#endif
/* Tightly coupled RAM where the board has it, so the buffer does not eat the heap. */
#if defined(__ZEPHYR__)
    #if DT_NODE_HAS_STATUS_OKAY(DT_CHOSEN(zephyr_dtcm))
        #define TRACE_SECTION __dtcm_noinit_section
    #endif
#endif
#ifndef TRACE_SECTION
    #define TRACE_SECTION
#endif

#ifdef CONFIG_ESE_TRACE_EVENTS
    #define TRACE_EVENTS CONFIG_ESE_TRACE_EVENTS
#else
    #define TRACE_EVENTS 12288
#endif
#define MAX_LABELS 64
#define KIND_MARK  3u
#define SIZE_MASK  0x1fffffffu

typedef struct {
    uint32_t t_us;
    uint32_t info;   /* kind in bits 31:30; for marks bit 29 = end, else size */
    uint32_t heap;   /* bytes allocated above the trace start */
} ev_t;

static const char *const steps[] = {
    "SendTls13ClientHello", "DoTls13ClientHello",
    "SendTls13ServerHello", "DoTls13ServerHello",
    "SendTls13EncryptedExtensions", "DoTls13EncryptedExtensions",
    "SendTls13CertificateRequest", "DoTls13CertificateRequest",
    "SendTls13Certificate", "DoTls13Certificate", "ProcessPeerCerts",
    "SendTls13CertificateVerify", "DoTls13CertificateVerify",
    "SendTls13Finished", "DoTls13Finished",
};

static TRACE_SECTION ev_t ev[TRACE_EVENTS];
static uint32_t n_ev;
static uint32_t dropped;
static const char *labels[MAX_LABELS];
static unsigned n_labels;
static int armed;
static int active;
static uint64_t t0;
static size_t base;

static void push(uint32_t info, size_t cur)
{
    if (n_ev >= TRACE_EVENTS) {
        dropped++;
        return;
    }
    ev[n_ev].t_us = (uint32_t)((ese_now_ns() - t0) / 1000u);
    ev[n_ev].info = info;
    ev[n_ev].heap = (uint32_t)(cur - base);
    n_ev++;
}

static unsigned label_id(const char *label)
{
    unsigned i;

    for (i = 0; i < n_labels; i++) {
        if (labels[i] == label) {
            return i;
        }
    }
    if (n_labels == MAX_LABELS) {
        return MAX_LABELS - 1;
    }
    labels[n_labels] = label;
    return n_labels++;
}

static void mark(const char *label, uint32_t end)
{
    if (active) {
        push((KIND_MARK << 30) | (end << 29) | label_id(label),
             ese_heap_cur());
    }
}

static void log_cb(const int level, const char *msg)
{
    const char *name;
    size_t len;
    uint32_t end;
    size_t i;

    (void)level;
    if (strncmp(msg, "wolfSSL Entering ", 17) == 0) {
        name = msg + 17;
        len = strlen(name);
        end = 0;
    }
    else if (strncmp(msg, "wolfSSL Leaving ", 16) == 0) {
        name = msg + 16;
        len = strcspn(name, ",");
        end = 1;
    }
    else {
        return;
    }
    for (i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        if (strlen(steps[i]) == len && memcmp(steps[i], name, len) == 0) {
            mark(steps[i], end);
            return;
        }
    }
}

void ese_trace_init(void)
{
    wolfSSL_SetLoggingCb(log_cb);
}

void ese_trace_arm(void)
{
    armed = 1;
}

void ese_trace_start(void)
{
    if (!armed) {
        return;
    }
    armed = 0;
    n_ev = 0;
    dropped = 0;
    n_labels = 0;
    t0 = ese_now_ns();
    base = ese_heap_cur();
    active = 1;
    wolfSSL_Debugging_ON();
}

void ese_trace_stop(void)
{
    if (active) {
        wolfSSL_Debugging_OFF();
        active = 0;
    }
}

void ese_trace_mark(const char *label)
{
    mark(label, 0);
}

void ese_trace_step(const char *label, int end)
{
    mark(label, end ? 1u : 0u);
}

void ese_trace_heap(int kind, size_t size, size_t cur)
{
    if (active) {
        push(((uint32_t)kind << 30) | ((uint32_t)size & SIZE_MASK), cur);
    }
}

/* T <seq> <t_us> <event> <size> <heap> <label>, then TEND <events> <dropped> */
void ese_trace_dump(int cfd)
{
    static const char *const kinds[] = { "alloc", "free", "realloc" };
    uint32_t i;

    for (i = 0; i < n_ev; i++) {
        uint32_t kind = ev[i].info >> 30;

        if (kind == KIND_MARK) {
            unsigned id = ev[i].info & 0xffu;
            ese_line_printf(cfd, "T %" PRIu32 " %" PRIu32 " %s 0 %" PRId32
                " %s", i, ev[i].t_us, (ev[i].info >> 29) & 1u ? "end" : "mark",
                (int32_t)ev[i].heap, id < n_labels ? labels[id] : "?");
        }
        else {
            ese_line_printf(cfd, "T %" PRIu32 " %" PRIu32 " %s %" PRIu32 " %"
                PRId32 " -", i, ev[i].t_us, kinds[kind],
                ev[i].info & SIZE_MASK, (int32_t)ev[i].heap);
        }
    }
    ese_line_printf(cfd, "TEND %" PRIu32 " %" PRIu32, n_ev, dropped);
    n_ev = 0;
}

#endif /* ESE_HEAP_TRACE */
