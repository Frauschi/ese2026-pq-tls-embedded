#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ese_certs.h"
#include "ese_devid.h"
#include "ese_meas.h"
#include "ese_platform.h"
#include "ese_tls.h"
#include "ese_trace.h"

#define CONNECT_TRIES 5

typedef struct {
    int fd;
    uint32_t tx;
    uint32_t rx;
} io_ctx_t;

static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    io_ctx_t *io = (io_ctx_t *)ctx;
    int n = ese_sock_recv(io->fd, buf, (size_t)sz);

    (void)ssl;
    if (n > 0) {
        io->rx += (uint32_t)n;
        return n;
    }
    return n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    io_ctx_t *io = (io_ctx_t *)ctx;
    int n = ese_sock_send(io->fd, buf, (size_t)sz);

    (void)ssl;
    if (n > 0) {
        io->tx += (uint32_t)n;
        return n;
    }
    return WOLFSSL_CBIO_ERR_CONN_RST;
}

static int load_own(WOLFSSL_CTX *ctx, const unsigned char *leaf,
                    unsigned int leaf_len, const unsigned char *inter,
                    unsigned int inter_len, const unsigned char *key,
                    unsigned int key_len)
{
    unsigned char *chain = malloc(leaf_len + inter_len);
    int ret;

    if (chain == NULL) {
        return MEMORY_E;
    }
    memcpy(chain, leaf, leaf_len);
    memcpy(chain + leaf_len, inter, inter_len);
    ese_trace_step("wolfSSL_CTX_use_certificate_chain_buffer", 0);
    ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, chain,
        (long)(leaf_len + inter_len), WOLFSSL_FILETYPE_ASN1);
    ese_trace_step("wolfSSL_CTX_use_certificate_chain_buffer", 1);
    free(chain);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }
    ese_trace_step("wolfSSL_CTX_use_PrivateKey_buffer", 0);
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, (long)key_len,
                                            WOLFSSL_FILETYPE_ASN1);
    ese_trace_step("wolfSSL_CTX_use_PrivateKey_buffer", 1);
    return ret;
}

int ese_tls_ctx_new(ese_tls_cfg_t *cfg)
{
    const ese_chain_certs_t *cc = &ese_chain_certs[cfg->chain];
    int server = cfg->role == ESE_ROLE_SERVER;
    int mutual = cfg->auth == ESE_AUTH_MUTUAL;
    int group = ese_kexs[cfg->kex].group;
    WOLFSSL_CTX *ctx;
    int ret;

    ese_trace_step("wolfSSL_CTX_new", 0);
    ctx = wolfSSL_CTX_new(server ? wolfTLSv1_3_server_method()
                                 : wolfTLSv1_3_client_method());
    ese_trace_step("wolfSSL_CTX_new", 1);
    if (ctx == NULL) {
        return MEMORY_E;
    }
    cfg->ctx = ctx;
    if (ESE_DEVID != INVALID_DEVID) {
        wolfSSL_CTX_SetDevId(ctx, ESE_DEVID);
    }
    wolfSSL_CTX_SetIORecv(ctx, io_recv);
    wolfSSL_CTX_SetIOSend(ctx, io_send);

    ese_trace_step("wolfSSL_CTX_set_cipher_list", 0);
    ret = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256");
    ese_trace_step("wolfSSL_CTX_set_cipher_list", 1);
    if (ret == WOLFSSL_SUCCESS) {
        ese_trace_step("wolfSSL_CTX_set_groups", 0);
        ret = wolfSSL_CTX_set_groups(ctx, &group, 1);
        ese_trace_step("wolfSSL_CTX_set_groups", 1);
    }
    if (ret == WOLFSSL_SUCCESS && server) {
        ret = load_own(ctx, cc->server, cc->server_len, cc->inter,
                       cc->inter_len, cc->server_key, cc->server_key_len);
    }
    else if (ret == WOLFSSL_SUCCESS && mutual) {
        ret = load_own(ctx, cc->client, cc->client_len, cc->inter,
                       cc->inter_len, cc->client_key, cc->client_key_len);
    }
    if (ret == WOLFSSL_SUCCESS && (!server || mutual)) {
        ese_trace_step("wolfSSL_CTX_load_verify_buffer", 0);
        ret = wolfSSL_CTX_load_verify_buffer(ctx, cc->root, (long)cc->root_len,
                                             WOLFSSL_FILETYPE_ASN1);
        ese_trace_step("wolfSSL_CTX_load_verify_buffer", 1);
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
            (server ? WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
    }
    else if (ret == WOLFSSL_SUCCESS) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    if (ret != WOLFSSL_SUCCESS) {
        ese_tls_ctx_free(cfg);
        return ret < 0 ? ret : WOLFSSL_FATAL_ERROR;
    }
    return 0;
}

void ese_tls_ctx_free(ese_tls_cfg_t *cfg)
{
    wolfSSL_CTX_free((WOLFSSL_CTX *)cfg->ctx);
    cfg->ctx = NULL;
}

static int ssl_err(WOLFSSL *ssl, int ret)
{
    int err = wolfSSL_get_error(ssl, ret);

    return err < 0 ? err : WOLFSSL_FATAL_ERROR;
}

static int read_full(WOLFSSL *ssl, unsigned char *buf, int len)
{
    int got = 0;
    int ret;

    while (got < len) {
        ret = wolfSSL_read(ssl, buf + got, len - got);
        if (ret <= 0) {
            return ssl_err(ssl, ret);
        }
        got += ret;
    }
    return 0;
}

static int write_msg(WOLFSSL *ssl, const char *tag)
{
    unsigned char msg[ESE_MSG_LEN];
    int ret;

    memset(msg, '.', sizeof(msg));
    memcpy(msg, tag, strlen(tag));
    ret = wolfSSL_write(ssl, msg, (int)sizeof(msg));
    return ret == (int)sizeof(msg) ? 0 : ssl_err(ssl, ret);
}

static void finish(WOLFSSL *ssl, io_ctx_t *io, ese_conn_res_t *res)
{
    ese_heap_stats_t hs;

    wolfSSL_free(ssl);
    ese_trace_mark("ssl_freed");
    if (io->fd >= 0) {
        ese_sock_close(io->fd);
    }
    ese_heap_window_get(&hs);
    res->tx = io->tx;
    res->rx = io->rx;
    res->heap_peak = hs.peak;
    res->heap_total = hs.total;
    res->heap_allocs = hs.allocs;
}

void ese_tls_client_conn(ese_tls_cfg_t *cfg, const char *ip, uint16_t port,
                         ese_conn_res_t *res)
{
    io_ctx_t io = { -1, 0, 0 };
    unsigned char reply[ESE_MSG_LEN];
    WOLFSSL *ssl = NULL;
    uint64_t t0;
    int ret;

    memset(res, 0, sizeof(*res));
    ese_heap_window_start();
    /* A refused SYN would desync host and DUT; retry with a fresh start time. */
    for (ret = 0; ret < CONNECT_TRIES; ret++) {
        t0 = ese_now_ns();
        io.fd = ese_sock_connect(ip, port);
        if (io.fd >= 0) {
            break;
        }
        ese_log("connect to %s:%u failed, retrying\n", ip, port);
        ese_sleep_ms(200);
    }
    if (io.fd < 0) {
        res->status = SOCKET_ERROR_E;
        finish(NULL, &io, res);
        return;
    }
    res->t_tcp = ese_now_ns() - t0;

    ese_trace_mark("ssl_new");
    ssl = wolfSSL_new((WOLFSSL_CTX *)cfg->ctx);
    if (ssl == NULL) {
        res->status = MEMORY_E;
        finish(NULL, &io, res);
        return;
    }
    wolfSSL_SetIOReadCtx(ssl, &io);
    wolfSSL_SetIOWriteCtx(ssl, &io);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, ESE_SERVER_NAME,
                   (word16)strlen(ESE_SERVER_NAME));
    wolfSSL_check_domain_name(ssl, ESE_SERVER_NAME);

    ese_trace_mark("handshake_start");
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        res->status = ssl_err(ssl, ret);
    }
    else {
        res->t_hs = ese_now_ns() - t0;
        ese_trace_mark("handshake_done");
        res->status = write_msg(ssl, "ESE-PING");
        if (res->status == 0) {
            res->status = read_full(ssl, reply, (int)sizeof(reply));
        }
        res->t_total = ese_now_ns() - t0;
        ese_trace_mark("app_data_done");
        if (res->status == 0 &&
            wolfSSL_shutdown(ssl) == WOLFSSL_SHUTDOWN_NOT_DONE) {
            wolfSSL_shutdown(ssl);
        }
        ese_trace_mark("shutdown_done");
    }
    finish(ssl, &io, res);
}

void ese_tls_server_conn(ese_tls_cfg_t *cfg, int fd, ese_conn_res_t *res)
{
    io_ctx_t io = { fd, 0, 0 };
    unsigned char req[ESE_MSG_LEN];
    WOLFSSL *ssl;
    uint64_t t0;
    int ret;

    memset(res, 0, sizeof(*res));
    ese_heap_window_start();
    t0 = ese_now_ns();
    ese_trace_mark("ssl_new");
    ssl = wolfSSL_new((WOLFSSL_CTX *)cfg->ctx);
    if (ssl == NULL) {
        res->status = MEMORY_E;
        finish(NULL, &io, res);
        return;
    }
    wolfSSL_SetIOReadCtx(ssl, &io);
    wolfSSL_SetIOWriteCtx(ssl, &io);

    ese_trace_mark("handshake_start");
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        res->status = ssl_err(ssl, ret);
    }
    else {
        res->t_hs = ese_now_ns() - t0;
        ese_trace_mark("handshake_done");
        res->status = read_full(ssl, req, (int)sizeof(req));
        if (res->status == 0) {
            res->status = write_msg(ssl, "ESE-PONG");
        }
        res->t_total = ese_now_ns() - t0;
        ese_trace_mark("app_data_done");
        if (res->status == 0) {
            /* Wait for the client's close_notify, then answer it. */
            wolfSSL_read(ssl, req, (int)sizeof(req));
            wolfSSL_shutdown(ssl);
        }
        ese_trace_mark("shutdown_done");
    }
    finish(ssl, &io, res);
}
