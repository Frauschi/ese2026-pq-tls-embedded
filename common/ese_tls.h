/* One TLS endpoint: context setup and a single measured connection. */
#ifndef ESE_TLS_H
#define ESE_TLS_H

#include <stdint.h>

#include "ese_algs.h"

#define ESE_MSG_LEN 64
#define ESE_SERVER_NAME "ese-server.local"

typedef struct {
    int chain;
    int kex;
    ese_auth_t auth;
    ese_role_t role;
    void *ctx;                 /* WOLFSSL_CTX */
} ese_tls_cfg_t;

typedef struct {
    int32_t status;            /* 0 or a wolfSSL error code */
    uint64_t t_tcp;            /* client: connect() duration */
    uint64_t t_hs;             /* start to handshake complete */
    uint64_t t_total;          /* client: TTFB; server: accept to reply sent */
    uint32_t tx;
    uint32_t rx;
    uint32_t heap_peak;
    uint32_t heap_total;
    uint32_t heap_allocs;
    uint32_t stack;
} ese_conn_res_t;

int ese_tls_ctx_new(ese_tls_cfg_t *cfg);
void ese_tls_ctx_free(ese_tls_cfg_t *cfg);

/* Client: connects to ip:port. Server: serves the already-accepted fd. */
void ese_tls_client_conn(ese_tls_cfg_t *cfg, const char *ip, uint16_t port,
                         ese_conn_res_t *res);
void ese_tls_server_conn(ese_tls_cfg_t *cfg, int fd, ese_conn_res_t *res);

#endif /* ESE_TLS_H */
