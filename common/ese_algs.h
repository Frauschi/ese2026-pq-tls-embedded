/* Algorithm, chain and key-exchange tables shared by certgen, DUT and host. */
#ifndef ESE_ALGS_H
#define ESE_ALGS_H

#include <stdint.h>

#if defined(WOLFSSL_FALCON_FFT_NEON)
    #define ESE_FALCON_FPR "neon"
#elif defined(WOLFSSL_FALCON_FPR_DOUBLE)
    #define ESE_FALCON_FPR "double"
#else
    #define ESE_FALCON_FPR "emulated"
#endif

typedef enum {
    ESE_SIG_ECDSA_P256 = 0,
    ESE_SIG_RSA3072,
    ESE_SIG_MLDSA44,
    ESE_SIG_FALCON512,
    ESE_SIG_SLHDSA_SHA2_128S,
    ESE_SIG_SLHDSA_SHA2_128F,
    ESE_SIG_SLHDSA_SHAKE_128S,
    ESE_SIG_SLHDSA_SHAKE_128F,
    ESE_SIG_LMS,
    ESE_SIG_XMSS,
    ESE_SIG_COUNT
} ese_sig_t;

typedef struct {
    const char *name;
    int stateful;
    int n;           /* samples for scenarios with this leaf */
    int mlkem_only;  /* too slow to cross with every key exchange */
} ese_sig_info_t;

typedef struct {
    const char *name;
    ese_sig_t ca;    /* root and intermediate */
    ese_sig_t leaf;  /* server and client end entities */
} ese_chain_t;

typedef struct {
    const char *name;
    uint16_t group;  /* wolfSSL named group */
} ese_kex_t;

typedef enum { ESE_AUTH_SERVER = 0, ESE_AUTH_MUTUAL = 1 } ese_auth_t;
typedef enum { ESE_ROLE_CLIENT = 0, ESE_ROLE_SERVER = 1 } ese_role_t;

#define ESE_N_DEFAULT 1000
#define ESE_N_SLHDSA_F 100
#define ESE_N_SLOW    25

extern const ese_sig_info_t ese_sigs[ESE_SIG_COUNT];
extern const ese_chain_t ese_chains[];
extern const int ese_chain_count;
extern const ese_kex_t ese_kexs[];
extern const int ese_kex_count;

const char *ese_auth_name(ese_auth_t a);
const char *ese_role_name(ese_role_t r);
int ese_chain_find(const char *name);
int ese_kex_find(const char *name);

/* Returns 0 when the chain/kex pair is not part of the matrix, else the N. */
int ese_scenario_n(int chain, int kex);

/* Same length as a TLS 1.3 CertificateVerify input with a SHA-256 transcript. */
#define ESE_BENCH_MSG_LEN 130
void ese_bench_msg(unsigned char *m);

#endif /* ESE_ALGS_H */
