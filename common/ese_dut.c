/* DUT side of the control protocol; identical on Linux and Zephyr. */
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ese_algbench.h"
#include "ese_algs.h"
#include "ese_ctrl.h"
#include "ese_dut.h"
#include "ese_meas.h"
#include "ese_platform.h"
#include "ese_tls.h"
#include "ese_trace.h"

#ifndef ESE_BUILD_TAG
    #define ESE_BUILD_TAG "dev"
#endif

#define ACCEPT_TIMEOUT_MS (60 * 1000)

#if defined(WOLFSSL_ARMASM) && !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
    #define ESE_HW_CRYPTO 1
#else
    #define ESE_HW_CRYPTO 0
#endif

#if defined(ESE_PQC_SMALLMEM)
    #define ESE_PQC_NAME "smallmem"
#elif defined(ESE_PQC_SMALLMEM_FAST)
    #define ESE_PQC_NAME "smallmem-fast"
#elif defined(ESE_PQC_CACHE)
    #define ESE_PQC_NAME "cache"
#elif defined(ESE_PQC_SMALL)
    #define ESE_PQC_NAME "small"
#else
    #define ESE_PQC_NAME "default"
#endif

#define ESE_STR_(x) #x
#define ESE_STR(x) ESE_STR_(x)
#if defined(CONFIG_NET_TCP_CONGESTION_INITIAL_WIN)
    #define ESE_TCP_CA "iw" ESE_STR(CONFIG_NET_TCP_CONGESTION_INITIAL_WIN) \
        "-ss" ESE_STR(CONFIG_NET_TCP_CONGESTION_INITIAL_SSTHRESH)
#elif defined(CONFIG_NET_TCP_CONGESTION_AVOIDANCE)
    #define ESE_TCP_CA "iw1-ss3"
#elif defined(__ZEPHYR__)
    #define ESE_TCP_CA "none"
#else
    #define ESE_TCP_CA "os"
#endif

#ifdef ESE_HEAP_TRACE
    #define ESE_TRACE_BUILD 1
#else
    #define ESE_TRACE_BUILD 0
#endif

static size_t stack_base;

typedef struct {
    ese_tls_cfg_t *cfg;
    const char *ip;
    uint16_t port;
    int fd;
    ese_conn_res_t *res;
} conn_job_t;

typedef struct {
    ese_alg_state_t *st;
    int n;
    ese_alg_sample_t *out;
} alg_job_t;

typedef struct {
    int idx;
    ese_alg_state_t **st;
    int ret;
} setup_job_t;

static size_t stack_selftest;

static void noop_job(void *arg)
{
    (void)arg;
}

/* Touches a known 2 KB so a broken stack probe shows up in HELLO. */
static void probe_job(void *arg)
{
    volatile unsigned char buf[2048];
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char)i;
    }
    *(volatile unsigned char *)arg = buf[sizeof(buf) - 1];
}

static void conn_job(void *arg)
{
    conn_job_t *j = (conn_job_t *)arg;

    if (j->cfg->role == ESE_ROLE_CLIENT) {
        ese_tls_client_conn(j->cfg, j->ip, j->port, j->res);
    }
    else {
        ese_tls_server_conn(j->cfg, j->fd, j->res);
    }
}

/* Setup signs and makes keys too, which needs the measured thread's stack. */
static void setup_job(void *arg)
{
    setup_job_t *j = (setup_job_t *)arg;

    j->ret = ese_alg_setup(j->idx, j->st);
}

static void alg_job(void *arg)
{
    alg_job_t *j = (alg_job_t *)arg;

    ese_alg_run(j->st, j->n, j->out);
}

/* Depth below the measured thread's entry frame; stack_base is reported, not subtracted. */
static uint32_t stack_net(size_t used)
{
    return (uint32_t)used;
}

/* TLS <dut_role> <chain> <kex> <auth> <n> <peer_ip> <port> */
static void cmd_tls(ese_line_t *lb, int cfd, char **tok, int ntok)
{
    ese_tls_cfg_t cfg;
    ese_heap_stats_t hs;
    ese_conn_res_t *res;
    conn_job_t job;
    size_t used;
    uint64_t t0;
    uint64_t t_ctx;
    int lfd = -1;
    int n;
    int i;
    int ret;

    memset(&cfg, 0, sizeof(cfg));
    if (ntok != 8) {
        ese_line_printf(cfd, "ERR usage");
        return;
    }
    cfg.role = strcmp(tok[1], "server") == 0 ? ESE_ROLE_SERVER
                                             : ESE_ROLE_CLIENT;
    cfg.chain = ese_chain_find(tok[2]);
    cfg.kex = ese_kex_find(tok[3]);
    cfg.auth = strcmp(tok[4], "mutual") == 0 ? ESE_AUTH_MUTUAL
                                             : ESE_AUTH_SERVER;
    n = atoi(tok[5]);
    if (cfg.chain < 0 || cfg.kex < 0 || n <= 0) {
        ese_line_printf(cfd, "ERR scenario");
        return;
    }
    res = calloc((size_t)n, sizeof(*res));
    if (res == NULL) {
        ese_line_printf(cfd, "ERR nomem");
        return;
    }

    ese_trace_start();
    ese_trace_mark("ctx_setup");
    ese_heap_window_start();
    t0 = ese_now_ns();
    ret = ese_tls_ctx_new(&cfg);
    t_ctx = ese_now_ns() - t0;
    ese_heap_window_get(&hs);
    ese_trace_mark("ctx_ready");
    ese_line_printf(cfd, "CTX %d %" PRIu32 " %" PRId32 " %" PRIu64, ret,
                    hs.peak, hs.held, t_ctx);
    if (ret == 0 && cfg.role == ESE_ROLE_SERVER) {
        lfd = ese_sock_listen((uint16_t)atoi(tok[7]));
        if (lfd < 0) {
            ret = SOCKET_ERROR_E;
        }
    }
    if (ret != 0) {
        ese_line_printf(cfd, "DONE 0 %d", ret);
        ese_tls_ctx_free(&cfg);
        ese_trace_stop();
        free(res);
        return;
    }
    ese_line_printf(cfd, "READY");
    if (cfg.role == ESE_ROLE_CLIENT) {
        char go[16];
        if (ese_line_read(lb, go, sizeof(go)) < 0 || strcmp(go, "GO") != 0) {
            n = 0;
        }
    }

    for (i = 0; i < n; i++) {
        job.cfg = &cfg;
        job.ip = tok[6];
        job.port = (uint16_t)atoi(tok[7]);
        job.res = &res[i];
        job.fd = -1;
        if (cfg.role == ESE_ROLE_SERVER) {
            job.fd = ese_sock_accept(lfd, ACCEPT_TIMEOUT_MS);
            if (job.fd < 0) {
                res[i].status = SOCKET_ERROR_E;
                break;
            }
        }
        used = 0;
        if (ese_run_measured(conn_job, &job, &used) != 0) {
            res[i].status = THREAD_CREATE_E;
        }
        res[i].stack = stack_net(used);
    }
    if (lfd >= 0) {
        ese_sock_close(lfd);
    }
    ese_tls_ctx_free(&cfg);
    ese_trace_mark("ctx_freed");
    ese_trace_stop();

    for (i = 0; i < n; i++) {
        ese_conn_res_t *r = &res[i];
        ese_line_printf(cfd, "R %d %" PRId32 " %" PRIu64 " %" PRIu64 " %"
            PRIu64 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32
            " %" PRIu32, i, r->status, r->t_tcp, r->t_hs, r->t_total, r->tx,
            r->rx, r->heap_peak, r->heap_total, r->heap_allocs, r->stack);
    }
    ese_line_printf(cfd, "DONE %d 0", n);
    free(res);
}

/* TRACE ARM traces the next TLS command; TRACE DUMP sends the events. */
static void cmd_trace(int cfd, const char *what)
{
#ifdef ESE_HEAP_TRACE
    if (strcmp(what, "ARM") == 0) {
        ese_trace_arm();
        ese_line_printf(cfd, "OK");
    }
    else if (strcmp(what, "DUMP") == 0) {
        ese_trace_dump(cfd);
    }
    else {
        ese_line_printf(cfd, "ERR usage");
    }
#else
    (void)what;
    ese_line_printf(cfd, "ERR notrace");
#endif
}

/* ALG <alg> <op> <n> */
static void cmd_alg(int cfd, char **tok, int ntok)
{
    ese_alg_sample_t *out;
    ese_alg_state_t *st = NULL;
    alg_job_t job;
    setup_job_t sj;
    size_t used = 0;
    uint32_t key_held;
    int idx;
    int n;
    int i;
    int ret;

    if (ntok != 4) {
        ese_line_printf(cfd, "ERR usage");
        return;
    }
    idx = ese_alg_find(tok[1], tok[2]);
    n = atoi(tok[3]);
    if (idx < 0 || n <= 0) {
        ese_line_printf(cfd, "ERR alg");
        return;
    }
    out = calloc((size_t)n, sizeof(*out));
    if (out == NULL) {
        ese_line_printf(cfd, "ERR nomem");
        return;
    }
    sj.idx = idx;
    sj.st = &st;
    sj.ret = 0;
    ret = ese_run_measured(setup_job, &sj, &used);
    if (ret == 0) {
        ret = sj.ret;
    }
    if (ret == 0) {
        job.st = st;
        job.n = n;
        job.out = out;
        ret = ese_run_measured(alg_job, &job, &used);
    }
    key_held = st != NULL ? ese_alg_key_held(st) : 0;
    ese_alg_teardown(st);
    if (ret != 0) {
        ese_line_printf(cfd, "DONE 0 %d", ret);
        free(out);
        return;
    }
    for (i = 0; i < n; i++) {
        ese_line_printf(cfd, "A %d %" PRId32 " %" PRIu64 " %" PRIu32 " %"
            PRIu32 " %" PRIu32, i, out[i].status, out[i].ns, out[i].heap_peak,
            out[i].heap_total, out[i].heap_allocs);
    }
    ese_line_printf(cfd, "STACK %" PRIu32, stack_net(used));
    ese_line_printf(cfd, "KEY %" PRIu32, key_held);
    ese_line_printf(cfd, "DONE %d 0", n);
    free(out);
}

static void session(int cfd)
{
    char line[ESE_LINE_MAX];
    char *tok[10];
    ese_line_t lb;
    int ntok;

    ese_line_init(&lb, cfd);
    while (ese_line_read(&lb, line, sizeof(line)) >= 0) {
        ntok = ese_line_split(line, tok, 10);
        if (ntok == 0) {
            continue;
        }
        if (strcmp(tok[0], "HELLO") == 0) {
            ese_line_printf(cfd, "OK platform=%s wolfssl=%s cpu_hz=%" PRIu32
                " build=%s stack_base=%u stack_selftest_2048=%u"
                " falcon_fpr=%s hw_crypto=%d trace=%d pqc_profile=%s tcp_ca=%s",
                ese_platform_name(), wolfSSL_lib_version(), ese_cpu_hz(),
                ESE_BUILD_TAG, (unsigned)stack_base,
                (unsigned)stack_selftest, ESE_FALCON_FPR, ESE_HW_CRYPTO,
                ESE_TRACE_BUILD,
                ESE_PQC_NAME, ESE_TCP_CA);
        }
        else if (strcmp(tok[0], "TIME") == 0 && ntok == 2) {
            ese_time_set(strtoull(tok[1], NULL, 10));
            ese_line_printf(cfd, "OK");
        }
        else if (strcmp(tok[0], "TLS") == 0) {
            cmd_tls(&lb, cfd, tok, ntok);
        }
        else if (strcmp(tok[0], "ALG") == 0) {
            cmd_alg(cfd, tok, ntok);
        }
        else if (strcmp(tok[0], "TRACE") == 0 && ntok == 2) {
            cmd_trace(cfd, tok[1]);
        }
        else if (strcmp(tok[0], "QUIT") == 0) {
            ese_line_printf(cfd, "BYE");
            break;
        }
        else {
            ese_line_printf(cfd, "ERR unknown");
        }
    }
}

int ese_dut_run(void)
{
    int lfd;
    int cfd;
    int i;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS || ese_heap_install() != 0) {
        ese_log("wolfSSL init failed\n");
        return -1;
    }
    ese_trace_init();
    for (i = 0; i < 4; i++) {
        size_t used = 0;
        ese_run_measured(noop_job, NULL, &used);
        if (i == 0 || used < stack_base) {
            stack_base = used;
        }
    }
    {
        unsigned char sink;
        size_t used = 0;

        ese_run_measured(probe_job, &sink, &used);
        stack_selftest = stack_net(used);
    }
    ese_log("ese-dut %s stack self-test %u (expect ~2048)\n", ESE_BUILD_TAG,
            (unsigned)stack_selftest);
    lfd = ese_sock_listen(ESE_CTRL_PORT);
    if (lfd < 0) {
        ese_log("control listen failed\n");
        return -1;
    }
    ese_log("ese-dut ready on port %d\n", ESE_CTRL_PORT);
    for (;;) {
        cfd = ese_sock_accept(lfd, 0);
        if (cfd < 0) {
            continue;
        }
        ese_log("host connected\n");
        session(cfd);
        ese_sock_close(cfd);
        ese_log("host disconnected\n");
    }
}
