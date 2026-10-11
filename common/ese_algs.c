#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "ese_algs.h"

const ese_sig_info_t ese_sigs[ESE_SIG_COUNT] = {
    [ESE_SIG_ECDSA_P256]        = { "ecdsa_p256",        0, ESE_N_DEFAULT,  0 },
    [ESE_SIG_RSA3072]           = { "rsa3072",           0, ESE_N_DEFAULT,  0 },
    [ESE_SIG_MLDSA44]           = { "mldsa44",           0, ESE_N_DEFAULT,  0 },
    [ESE_SIG_FALCON512]         = { "falcon512",         0, ESE_N_DEFAULT,  0 },
    [ESE_SIG_SLHDSA_SHA2_128S]  = { "slhdsa_sha2_128s",  0, ESE_N_SLOW,     1 },
    [ESE_SIG_SLHDSA_SHA2_128F]  = { "slhdsa_sha2_128f",  0, ESE_N_SLHDSA_F, 0 },
    [ESE_SIG_SLHDSA_SHAKE_128S] = { "slhdsa_shake_128s", 0, ESE_N_SLOW,     1 },
    [ESE_SIG_SLHDSA_SHAKE_128F] = { "slhdsa_shake_128f", 0, ESE_N_SLHDSA_F, 0 },
    [ESE_SIG_LMS]               = { "lms",               1, ESE_N_DEFAULT,  0 },
    [ESE_SIG_XMSS]              = { "xmss",              1, ESE_N_DEFAULT,  0 },
};

const ese_chain_t ese_chains[] = {
    { "ecdsa_p256",        ESE_SIG_ECDSA_P256,        ESE_SIG_ECDSA_P256 },
    { "rsa3072",           ESE_SIG_RSA3072,           ESE_SIG_RSA3072 },
    { "mldsa44",           ESE_SIG_MLDSA44,           ESE_SIG_MLDSA44 },
    { "falcon512",         ESE_SIG_FALCON512,         ESE_SIG_FALCON512 },
    { "slhdsa_sha2_128s",  ESE_SIG_SLHDSA_SHA2_128S,  ESE_SIG_SLHDSA_SHA2_128S },
    { "slhdsa_sha2_128f",  ESE_SIG_SLHDSA_SHA2_128F,  ESE_SIG_SLHDSA_SHA2_128F },
    { "slhdsa_shake_128s", ESE_SIG_SLHDSA_SHAKE_128S, ESE_SIG_SLHDSA_SHAKE_128S },
    { "slhdsa_shake_128f", ESE_SIG_SLHDSA_SHAKE_128F, ESE_SIG_SLHDSA_SHAKE_128F },
    { "lms+mldsa44",           ESE_SIG_LMS,  ESE_SIG_MLDSA44 },
    { "lms+slhdsa_sha2_128s",  ESE_SIG_LMS,  ESE_SIG_SLHDSA_SHA2_128S },
    { "lms+slhdsa_sha2_128f",  ESE_SIG_LMS,  ESE_SIG_SLHDSA_SHA2_128F },
    { "lms+slhdsa_shake_128s", ESE_SIG_LMS,  ESE_SIG_SLHDSA_SHAKE_128S },
    { "lms+slhdsa_shake_128f", ESE_SIG_LMS,  ESE_SIG_SLHDSA_SHAKE_128F },
    { "xmss+mldsa44",           ESE_SIG_XMSS, ESE_SIG_MLDSA44 },
    { "xmss+slhdsa_sha2_128s",  ESE_SIG_XMSS, ESE_SIG_SLHDSA_SHA2_128S },
    { "xmss+slhdsa_sha2_128f",  ESE_SIG_XMSS, ESE_SIG_SLHDSA_SHA2_128F },
    { "xmss+slhdsa_shake_128s", ESE_SIG_XMSS, ESE_SIG_SLHDSA_SHAKE_128S },
    { "xmss+slhdsa_shake_128f", ESE_SIG_XMSS, ESE_SIG_SLHDSA_SHAKE_128F },
};
const int ese_chain_count = (int)(sizeof(ese_chains) / sizeof(ese_chains[0]));

const ese_kex_t ese_kexs[] = {
    { "secp256r1",      WOLFSSL_ECC_SECP256R1 },
    { "x25519",         WOLFSSL_ECC_X25519 },
    { "mlkem768",       WOLFSSL_ML_KEM_768 },
    { "x25519mlkem768", WOLFSSL_X25519MLKEM768 },
};
const int ese_kex_count = (int)(sizeof(ese_kexs) / sizeof(ese_kexs[0]));

const char *ese_auth_name(ese_auth_t a)
{
    return a == ESE_AUTH_MUTUAL ? "mutual" : "server";
}

const char *ese_role_name(ese_role_t r)
{
    return r == ESE_ROLE_SERVER ? "server" : "client";
}

int ese_chain_find(const char *name)
{
    int i;

    for (i = 0; i < ese_chain_count; i++) {
        if (strcmp(ese_chains[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int ese_kex_find(const char *name)
{
    int i;

    for (i = 0; i < ese_kex_count; i++) {
        if (strcmp(ese_kexs[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

int ese_scenario_n(int chain, int kex)
{
    const ese_sig_info_t *leaf = &ese_sigs[ese_chains[chain].leaf];

    if (leaf->mlkem_only && ese_kexs[kex].group != WOLFSSL_ML_KEM_768) {
        return 0;
    }
    return leaf->n;
}

void ese_bench_msg(unsigned char *m)
{
    int i;

    for (i = 0; i < ESE_BENCH_MSG_LEN; i++) {
        m[i] = (unsigned char)(i * 7 + 3);
    }
}
