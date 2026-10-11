/* Host helper: drives a DUT over the control channel, plays the TLS peer and writes CSVs. */
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "ese_algbench.h"
#include "ese_algs.h"
#include "ese_ctrl.h"
#include "ese_platform.h"
#include "ese_tls.h"

#define HOST_PORT_BASE 4400
#define DONE_KEYS_MAX 4096

typedef struct {
    const char *dut_ip;
    const char *host_ip;
    const char *out;
    const char *label;
    const char *f_chain;
    const char *f_kex;
    const char *f_auth;
    const char *f_role;
    const char *f_alg;
    const char *f_op;
    int n_override;
    double scale;
    int do_tls;
    int do_alg;
    int dry_run;
    int heap_trace;
    int host_port;
    double rtt_ms;
    int group_msgs;
} opts_t;

typedef struct {
    int32_t status;
    uint64_t t_tcp;
    uint64_t t_hs;
    uint64_t t_total;
    uint32_t tx;
    uint32_t rx;
    uint32_t heap_peak;
    uint32_t heap_total;
    uint32_t heap_allocs;
    uint32_t stack;
} dut_row_t;

static opts_t o;
static int cfd = -1;
static ese_line_t lb;
static char platform[64] = "unknown";
/* Older DUTs do not report a profile; they all ran smallmem. */
static char pqc_profile[32] = "smallmem";
static char *done_keys[DONE_KEYS_MAX];
static int done_count;

static void die(const char *msg)
{
    fprintf(stderr, "ese_host: %s\n", msg);
    exit(1);
}

static int ctrl_read(char *line, size_t max)
{
    int n = ese_line_read(&lb, line, max);

    if (n < 0) {
        die("control connection lost");
    }
    return n;
}

static int filter_ok(const char *filter, const char *value)
{
    char buf[512];
    char *tok;
    char *save = NULL;

    if (filter == NULL) {
        return 1;
    }
    snprintf(buf, sizeof(buf), "%s", filter);
    for (tok = strtok_r(buf, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        if (strcmp(tok, value) == 0) {
            return 1;
        }
    }
    return 0;
}

static int scaled_n(int n)
{
    if (o.n_override > 0) {
        return o.n_override;
    }
    n = (int)(n * o.scale + 0.5);
    return n < 1 ? 1 : n;
}

static FILE *open_csv(const char *name, const char *header)
{
    char path[512];
    struct stat sb;
    FILE *f;
    int fresh;

    snprintf(path, sizeof(path), "%s/%s", o.out, name);
    fresh = stat(path, &sb) != 0 || sb.st_size == 0;
    f = fopen(path, "a");
    if (f == NULL) {
        die("cannot open csv");
    }
    if (fresh) {
        fprintf(f, "%s\n", header);
    }
    return f;
}

/* A scenario counts as done once its rows exist in tls.csv, so reruns resume. */
static void load_done_keys(void)
{
    char path[512];
    char line[1024];
    char key[256];
    char *f[8];
    FILE *fp;
    int i;
    int nf;

    snprintf(path, sizeof(path), "%s/tls.csv", o.out);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL && done_count < DONE_KEYS_MAX) {
        char *p = line;
        nf = 0;
        while (nf < 8 && (f[nf] = strsep(&p, ",")) != NULL) {
            nf++;
        }
        if (nf < 8 || strcmp(f[0], "platform") == 0) {
            continue;
        }
        snprintf(key, sizeof(key), "%s|%s|%s|%s", f[1], f[4], f[5], f[6]);
        for (i = 0; i < done_count; i++) {
            if (strcmp(done_keys[i], key) == 0) {
                break;
            }
        }
        if (i == done_count) {
            done_keys[done_count++] = strdup(key);
        }
    }
    fclose(fp);
}

static int is_done(const char *key)
{
    int i;

    for (i = 0; i < done_count; i++) {
        if (strcmp(done_keys[i], key) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

static void summarize(const char *what, uint64_t *v, int n, int fails)
{
    if (n == 0) {
        printf("  %-60s all %d failed\n", what, fails);
        return;
    }
    qsort(v, (size_t)n, sizeof(v[0]), cmp_u64);
    printf("  %-60s n=%-4d fail=%-3d median %9.3f ms  p99 %9.3f ms\n", what, n,
           fails, v[n / 2] / 1e6, v[(n * 99) / 100 >= n ? n - 1 :
           (n * 99) / 100] / 1e6);
    fflush(stdout);
}

/* A re-plugged NIC drops its qdisc; stop before such rows reach tls.csv. */
static void check_rtt(uint64_t *tcp, int n)
{
    double ms;

    if (o.rtt_ms < 0 || n == 0) {
        return;
    }
    qsort(tcp, (size_t)n, sizeof(tcp[0]), cmp_u64);
    ms = tcp[n / 2] / 1e6;
    if (ms < o.rtt_ms * 0.9 || ms > o.rtt_ms * 1.1 + 2.0) {
        fprintf(stderr, "median TCP connect %.3f ms does not match --rtt-ms %g; "
                "check scripts/netem.sh show\n", ms, o.rtt_ms);
        exit(1);
    }
}

static int read_dut_rows(dut_row_t *rows, int n)
{
    char line[ESE_LINE_MAX];
    char *tok[16];
    int got = 0;
    int ntok;
    int i;

    for (;;) {
        ctrl_read(line, sizeof(line));
        ntok = ese_line_split(line, tok, 16);
        if (ntok >= 1 && strcmp(tok[0], "DONE") == 0) {
            return got;
        }
        if (ntok != 12 || strcmp(tok[0], "R") != 0) {
            continue;
        }
        i = atoi(tok[1]);
        if (i < 0 || i >= n) {
            continue;
        }
        rows[i].status = (int32_t)atoi(tok[2]);
        rows[i].t_tcp = strtoull(tok[3], NULL, 10);
        rows[i].t_hs = strtoull(tok[4], NULL, 10);
        rows[i].t_total = strtoull(tok[5], NULL, 10);
        rows[i].tx = (uint32_t)strtoul(tok[6], NULL, 10);
        rows[i].rx = (uint32_t)strtoul(tok[7], NULL, 10);
        rows[i].heap_peak = (uint32_t)strtoul(tok[8], NULL, 10);
        rows[i].heap_total = (uint32_t)strtoul(tok[9], NULL, 10);
        rows[i].heap_allocs = (uint32_t)strtoul(tok[10], NULL, 10);
        rows[i].stack = (uint32_t)strtoul(tok[11], NULL, 10);
        got++;
    }
}

/* Reads one TRACE DUMP into heap_trace.csv; returns the peak heap seen. */
static long read_trace(const char *key, FILE *tr_csv, long *events,
                       long *dropped)
{
    char line[ESE_LINE_MAX];
    char *tok[8];
    long peak = 0;
    int ntok;

    ese_line_printf(cfd, "TRACE DUMP");
    for (;;) {
        ctrl_read(line, sizeof(line));
        ntok = ese_line_split(line, tok, 8);
        if (ntok == 3 && strcmp(tok[0], "TEND") == 0) {
            *events = atol(tok[1]);
            *dropped = atol(tok[2]);
            fflush(tr_csv);
            return peak;
        }
        if (ntok != 7 || strcmp(tok[0], "T") != 0) {
            continue;
        }
        if (atol(tok[5]) > peak) {
            peak = atol(tok[5]);
        }
        fprintf(tr_csv, "%s,%s,%s,%s,%s,%s,%s\n", key, tok[1], tok[2],
                tok[3], tok[4], tok[5], strcmp(tok[6], "-") ? tok[6] : "");
    }
}

static void run_tls(int chain, int kex, ese_auth_t auth, ese_role_t dut_role,
                    int n, FILE *csv, FILE *ctx_csv, FILE *tr_csv)
{
    const ese_chain_t *ch = &ese_chains[chain];
    ese_tls_cfg_t cfg;
    ese_conn_res_t *h = calloc((size_t)n, sizeof(*h));
    dut_row_t *d = calloc((size_t)n, sizeof(*d));
    uint64_t *ttfb = calloc((size_t)n, sizeof(*ttfb));
    uint64_t *tcp = calloc((size_t)n, sizeof(*tcp));
    char line[ESE_LINE_MAX];
    char *tok[8];
    char what[160];
    uint16_t port = (uint16_t)o.host_port;
    int lfd = -1;
    int ok = 0;
    int fails = 0;
    int i;

    if (h == NULL || d == NULL || ttfb == NULL || tcp == NULL) {
        die("out of memory");
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.chain = chain;
    cfg.kex = kex;
    cfg.auth = auth;
    cfg.role = dut_role == ESE_ROLE_SERVER ? ESE_ROLE_CLIENT : ESE_ROLE_SERVER;
    if (ese_tls_ctx_new(&cfg) != 0) {
        die("host ctx setup failed");
    }
    if (o.group_msgs) {
        wolfSSL_CTX_set_group_messages((WOLFSSL_CTX *)cfg.ctx);
    }
    if (cfg.role == ESE_ROLE_SERVER) {
        lfd = ese_sock_listen(port);
        if (lfd < 0) {
            die("host listen failed");
        }
    }

    if (tr_csv != NULL) {
        ese_line_printf(cfd, "TRACE ARM");
        ctrl_read(line, sizeof(line));
        if (strcmp(line, "OK") != 0) {
            die("DUT has no heap trace; flash a -trace build");
        }
    }
    ese_line_printf(cfd, "TLS %s %s %s %s %d %s %u", ese_role_name(dut_role),
                    ch->name, ese_kexs[kex].name, ese_auth_name(auth), n,
                    o.host_ip, port);
    ctrl_read(line, sizeof(line));
    if (ese_line_split(line, tok, 8) == 5 && strcmp(tok[0], "CTX") == 0) {
        fprintf(ctx_csv, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", platform, ch->name,
                ese_kexs[kex].name, ese_auth_name(auth),
                ese_role_name(dut_role), tok[1], tok[2], tok[3], tok[4]);
        fflush(ctx_csv);
    }
    ctrl_read(line, sizeof(line));
    if (strcmp(line, "READY") != 0) {
        fprintf(stderr, "DUT refused scenario: %s\n", line);
        goto out;
    }
    if (dut_role == ESE_ROLE_CLIENT) {
        ese_line_printf(cfd, "GO");
    }

    for (i = 0; i < n; i++) {
        if (dut_role == ESE_ROLE_SERVER) {
            ese_tls_client_conn(&cfg, o.dut_ip, port, &h[i]);
        }
        else {
            int fd = ese_sock_accept(lfd, 60 * 1000);
            if (fd < 0) {
                h[i].status = -1;
                break;
            }
            ese_tls_server_conn(&cfg, fd, &h[i]);
        }
    }
    read_dut_rows(d, n);
    if (tr_csv != NULL) {
        char key[160];
        long events;
        long dropped;
        long peak;

        snprintf(key, sizeof(key), "%s,%s,%s,%s,%s", platform, ch->name,
                 ese_kexs[kex].name, ese_auth_name(auth),
                 ese_role_name(dut_role));
        peak = read_trace(key, tr_csv, &events, &dropped);
        printf("  trace: %ld events, peak %ld B%s\n", events, peak,
               dropped ? " (buffer full, events dropped)" : "");
    }

    for (i = 0; i < n; i++) {
        if (d[i].status == 0 && h[i].status == 0) {
            tcp[ok++] = dut_role == ESE_ROLE_CLIENT ? d[i].t_tcp : h[i].t_tcp;
        }
    }
    check_rtt(tcp, ok);
    ok = 0;

    for (i = 0; i < n; i++) {
        const ese_conn_res_t *cli = NULL;
        const ese_conn_res_t *srv = NULL;
        ese_conn_res_t dr;
        uint32_t c2s;
        uint32_t s2c;

        memset(&dr, 0, sizeof(dr));
        dr.t_tcp = d[i].t_tcp;
        dr.t_hs = d[i].t_hs;
        dr.t_total = d[i].t_total;
        if (dut_role == ESE_ROLE_CLIENT) {
            cli = &dr;
            srv = &h[i];
            c2s = d[i].tx;
            s2c = d[i].rx;
        }
        else {
            cli = &h[i];
            srv = &dr;
            c2s = d[i].rx;
            s2c = d[i].tx;
        }
        fprintf(csv, "%s,%s,%s,%s,%s,%s,%s,%d,%d,%" PRId32 ",%" PRId32 ",%"
                PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%"
                PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%"
                PRIu32 "\n", platform, ch->name, ese_sigs[ch->ca].name,
                ese_sigs[ch->leaf].name, ese_kexs[kex].name,
                ese_auth_name(auth), ese_role_name(dut_role), i, n,
                d[i].status, h[i].status, cli->t_total, cli->t_tcp, cli->t_hs,
                srv->t_hs, srv->t_total, c2s, s2c, d[i].heap_peak,
                d[i].heap_total, d[i].heap_allocs, d[i].stack);
        if (d[i].status == 0 && h[i].status == 0) {
            ttfb[ok++] = cli->t_total;
        }
        else {
            fails++;
        }
    }
    fflush(csv);
    snprintf(what, sizeof(what), "%s %s %s dut=%s", ch->name,
             ese_kexs[kex].name, ese_auth_name(auth), ese_role_name(dut_role));
    summarize(what, ttfb, ok, fails);

out:
    if (lfd >= 0) {
        ese_sock_close(lfd);
    }
    ese_tls_ctx_free(&cfg);
    free(h);
    free(d);
    free(ttfb);
    free(tcp);
}

static void tls_matrix(void)
{
    FILE *csv = NULL;
    FILE *ctx_csv = NULL;
    FILE *tr_csv = NULL;
    char key[256];
    int c;
    int k;
    int a;
    int r;
    int n;
    int total = 0;
    long hs = 0;

    if (!o.dry_run) {
        csv = open_csv("tls.csv", "platform,chain,ca_alg,leaf_alg,kex,auth,"
            "dut_role,iter,n,dut_status,host_status,ttfb_ns,tcp_ns,"
            "client_hs_ns,server_hs_ns,server_total_ns,c2s_bytes,s2c_bytes,"
            "dut_heap_peak,dut_heap_total,dut_heap_allocs,dut_stack");
        ctx_csv = open_csv("tls_ctx.csv", "platform,chain,kex,auth,dut_role,"
            "status,heap_peak,heap_held,setup_ns");
        if (o.heap_trace) {
            tr_csv = open_csv("heap_trace.csv", "platform,chain,kex,auth,"
                "dut_role,seq,t_us,event,size,heap,label");
        }
        load_done_keys();
    }
    for (c = 0; c < ese_chain_count; c++) {
        if (!filter_ok(o.f_chain, ese_chains[c].name)) continue;
        for (k = 0; k < ese_kex_count; k++) {
            if (!filter_ok(o.f_kex, ese_kexs[k].name)) continue;
            n = ese_scenario_n(c, k);
            if (n == 0) continue;
            n = o.heap_trace ? 1 : scaled_n(n);
            for (a = 0; a < 2; a++) {
                if (!filter_ok(o.f_auth, ese_auth_name((ese_auth_t)a))) continue;
                for (r = 0; r < 2; r++) {
                    if (!filter_ok(o.f_role, ese_role_name((ese_role_t)r)))
                        continue;
                    snprintf(key, sizeof(key), "%s|%s|%s|%s",
                             ese_chains[c].name, ese_kexs[k].name,
                             ese_auth_name((ese_auth_t)a),
                             ese_role_name((ese_role_t)r));
                    total++;
                    hs += n;
                    if (o.dry_run) {
                        printf("  %-60s n=%d\n", key, n);
                        continue;
                    }
                    if (is_done(key)) {
                        printf("  %-60s done, skipped\n", key);
                        continue;
                    }
                    run_tls(c, k, (ese_auth_t)a, (ese_role_t)r, n, csv,
                            ctx_csv, tr_csv);
                }
            }
        }
    }
    printf("%d TLS scenarios, %ld handshakes\n", total, hs);
    if (csv != NULL) fclose(csv);
    if (ctx_csv != NULL) fclose(ctx_csv);
    if (tr_csv != NULL) fclose(tr_csv);
}

static void alg_matrix(void)
{
    FILE *csv = NULL;
    char line[ESE_LINE_MAX];
    char *tok[10];
    char what[96];
    uint64_t *v;
    int i;
    int n;
    int ntok;
    int ok;
    int fails;
    unsigned long stack;
    unsigned long key_held;

    if (!o.dry_run) {
        csv = open_csv("alg.csv", "platform,alg,op,iter,n,status,ns,"
                       "heap_peak,heap_total,heap_allocs,stack,key_held,variant");
    }
    for (i = 0; i < ese_alg_op_count; i++) {
        if (!filter_ok(o.f_alg, ese_alg_ops[i].alg)) continue;
        if (!filter_ok(o.f_op, ese_alg_ops[i].op)) continue;
        n = scaled_n(ese_alg_default_n(i));
        snprintf(what, sizeof(what), "%s %s", ese_alg_ops[i].alg,
                 ese_alg_ops[i].op);
        if (o.dry_run) {
            printf("  %-60s n=%d\n", what, n);
            continue;
        }
        v = calloc((size_t)n, sizeof(*v));
        if (v == NULL) die("out of memory");
        ok = 0;
        fails = 0;
        stack = 0;
        key_held = 0;
        ese_line_printf(cfd, "ALG %s %s %d", ese_alg_ops[i].alg,
                        ese_alg_ops[i].op, n);
        /* Rows are buffered until the stack figure arrives. */
        {
            char (*rows)[ESE_LINE_MAX] = calloc((size_t)n, ESE_LINE_MAX);
            int nrows = 0;
            if (rows == NULL) die("out of memory");
            for (;;) {
                ctrl_read(line, sizeof(line));
                if (strncmp(line, "DONE", 4) == 0) break;
                if (strncmp(line, "STACK ", 6) == 0) {
                    stack = strtoul(line + 6, NULL, 10);
                    continue;
                }
                if (strncmp(line, "KEY ", 4) == 0) {
                    key_held = strtoul(line + 4, NULL, 10);
                    continue;
                }
                if (strncmp(line, "A ", 2) == 0 && nrows < n) {
                    snprintf(rows[nrows++], ESE_LINE_MAX, "%s", line);
                }
            }
            for (int r = 0; r < nrows; r++) {
                ntok = ese_line_split(rows[r], tok, 10);
                if (ntok != 7) continue;
                fprintf(csv, "%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%lu,%lu,%s\n",
                        platform, ese_alg_ops[i].alg, ese_alg_ops[i].op,
                        tok[1], n, tok[2], tok[3], tok[4], tok[5], tok[6],
                        stack, key_held, pqc_profile);
                if (atoi(tok[2]) == 0) v[ok++] = strtoull(tok[3], NULL, 10);
                else fails++;
            }
            free(rows);
        }
        fflush(csv);
        summarize(what, v, ok, fails);
        free(v);
    }
    if (csv != NULL) fclose(csv);
}

static void write_meta(const char *hello)
{
    char path[512];
    FILE *f;
    time_t now = time(NULL);

    snprintf(path, sizeof(path), "%s/meta.txt", o.out);
    f = fopen(path, "a");
    if (f == NULL) die("cannot write meta.txt");
    fprintf(f, "date=%s", ctime(&now));
    fprintf(f, "label=%s\ndut_ip=%s\nhost_ip=%s\n", platform, o.dut_ip,
            o.host_ip);
    fprintf(f, "dut_hello=%s\n", hello);
    fprintf(f, "host=%s host_wolfssl=%s host_falcon_fpr=%s\n",
            ese_platform_name(), wolfSSL_lib_version(), ESE_FALCON_FPR);
#ifdef ESE_GIT_REV
    fprintf(f, "ese_git=%s\n", ESE_GIT_REV);
#endif
#ifdef ESE_WOLFSSL_GIT_REV
    fprintf(f, "wolfssl_git=%s\n", ESE_WOLFSSL_GIT_REV);
#endif
    fprintf(f, "scale=%g n_override=%d heap_trace=%d host_port=%d rtt_ms=%g "
            "group_msgs=%d\n\n", o.scale, o.n_override, o.heap_trace,
            o.host_port, o.rtt_ms, o.group_msgs);
    fclose(f);
}

static void usage(void)
{
    fprintf(stderr,
        "usage: ese_host --dut IP --host-ip IP [options]\n"
        "  --out DIR        results directory (default results/<label>/<date>)\n"
        "  --label NAME     platform label for the CSVs (default: DUT platform)\n"
        "  --tls / --alg    run the TLS matrix and/or the algorithm matrix\n"
        "  --chain LIST     comma-separated chain filter\n"
        "  --kex LIST       comma-separated key-exchange filter\n"
        "  --auth LIST      server,mutual\n"
        "  --role LIST      DUT role: client,server\n"
        "  --alg-filter L   comma-separated algorithm filter for --alg\n"
        "  --op-filter L    comma-separated operation filter for --alg\n"
        "  --n N            fixed sample count per scenario\n"
        "  --scale F        multiply the default sample counts (pilot runs)\n"
        "  --host-port P    port the host's TLS server listens on (default 4400 +\n"
        "                   last octet of the DUT IP, so parallel runs never collide)\n"
        "  --rtt-ms R       RTT added by scripts/netem.sh; stop if the TCP connect\n"
        "                   time does not match it\n"
        "  --group-messages host sends each handshake flight in one write\n"
        "  --dry-run        list the scenarios without connecting\n"
        "  --heap-trace     one traced handshake per scenario into heap_trace.csv\n"
        "                   (needs a -trace DUT build; implies --tls, n=1)\n");
    exit(2);
}

int main(int argc, char **argv)
{
    static const struct option lo[] = {
        { "dut", 1, 0, 'd' }, { "host-ip", 1, 0, 'H' }, { "out", 1, 0, 'o' },
        { "label", 1, 0, 'l' }, { "tls", 0, 0, 't' }, { "alg", 0, 0, 'a' },
        { "chain", 1, 0, 'c' }, { "kex", 1, 0, 'k' }, { "auth", 1, 0, 'u' },
        { "role", 1, 0, 'r' }, { "alg-filter", 1, 0, 'f' }, { "n", 1, 0, 'n' },
        { "scale", 1, 0, 's' }, { "dry-run", 0, 0, 'D' },
        { "heap-trace", 0, 0, 'T' }, { "host-port", 1, 0, 'P' },
        { "rtt-ms", 1, 0, 'R' }, { "op-filter", 1, 0, 'O' },
        { "group-messages", 0, 0, 'G' }, { 0, 0, 0, 0 }
    };
    char line[ESE_LINE_MAX];
    char outbuf[512];
    struct timeval tv = { 3 * 3600, 0 };
    int ch;

    o.scale = 1.0;
    o.rtt_ms = -1;
    while ((ch = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (ch) {
        case 'd': o.dut_ip = optarg; break;
        case 'H': o.host_ip = optarg; break;
        case 'o': o.out = optarg; break;
        case 'l': o.label = optarg; break;
        case 't': o.do_tls = 1; break;
        case 'a': o.do_alg = 1; break;
        case 'c': o.f_chain = optarg; break;
        case 'k': o.f_kex = optarg; break;
        case 'u': o.f_auth = optarg; break;
        case 'r': o.f_role = optarg; break;
        case 'f': o.f_alg = optarg; break;
        case 'O': o.f_op = optarg; break;
        case 'n': o.n_override = atoi(optarg); break;
        case 's': o.scale = atof(optarg); break;
        case 'D': o.dry_run = 1; break;
        case 'T': o.heap_trace = 1; o.do_tls = 1; break;
        case 'P': o.host_port = atoi(optarg); break;
        case 'R': o.rtt_ms = atof(optarg); break;
        case 'G': o.group_msgs = 1; break;
        default: usage();
        }
    }
    if (!o.do_tls && !o.do_alg) {
        usage();
    }
    if (o.dry_run) {
        if (o.do_alg) alg_matrix();
        if (o.do_tls) tls_matrix();
        return 0;
    }
    if (o.dut_ip == NULL || o.host_ip == NULL) {
        usage();
    }
    if (o.host_port == 0) {
        const char *dot = strrchr(o.dut_ip, '.');
        o.host_port = HOST_PORT_BASE + (dot != NULL ? atoi(dot + 1) : 0);
    }
    if (o.host_port <= 0 || o.host_port > 65535) {
        usage();
    }
    signal(SIGPIPE, SIG_IGN);
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        die("wolfSSL_Init failed");
    }

    cfd = ese_sock_connect(o.dut_ip, ESE_CTRL_PORT);
    if (cfd < 0) {
        die("cannot connect to DUT control port");
    }
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ese_line_init(&lb, cfd);
    ese_line_printf(cfd, "HELLO");
    ctrl_read(line, sizeof(line));
    printf("DUT: %s\n", line);
    if (o.label != NULL) {
        snprintf(platform, sizeof(platform), "%s", o.label);
    }
    else if (sscanf(line, "OK platform=%63s", platform) != 1) {
        die("bad HELLO reply");
    }
    {
        const char *p = strstr(line, " pqc_profile=");
        if (p != NULL) sscanf(p + 13, "%31s", pqc_profile);
    }
    ese_line_printf(cfd, "TIME %lld", (long long)time(NULL));
    ctrl_read(line, sizeof(line));

    if (o.out == NULL) {
        char date[32];
        time_t now = time(NULL);
        strftime(date, sizeof(date), "%Y%m%d-%H%M%S", localtime(&now));
        snprintf(outbuf, sizeof(outbuf), "results/%s/%s", platform, date);
        o.out = outbuf;
    }
    snprintf(line, sizeof(line), "mkdir -p '%s'", o.out);
    if (system(line) != 0) {
        die("cannot create output directory");
    }
    printf("writing to %s\n", o.out);
    ese_line_printf(cfd, "HELLO");
    ctrl_read(line, sizeof(line));
    write_meta(line);

    if (o.do_alg) alg_matrix();
    if (o.do_tls) tls_matrix();

    ese_line_printf(cfd, "QUIT");
    ese_sock_close(cfd);
    wolfSSL_Cleanup();
    return 0;
}
