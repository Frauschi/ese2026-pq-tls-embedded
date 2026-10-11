#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ese_algbench.h"
#include "ese_algs.h"
#include "ese_certs.h"
#include "ese_devid.h"
#include "ese_meas.h"
#include "ese_platform.h"

#define SIG_MAX 20000

enum {
    ALG_ECDSA, ALG_RSA, ALG_MLDSA, ALG_FALCON, ALG_SLH, ALG_LMS, ALG_XMSS,
    ALG_ECDH, ALG_X25519, ALG_MLKEM
};
enum { OP_KEYGEN, OP_SIGN, OP_VERIFY, OP_SHARED, OP_ENCAP, OP_DECAP };

const ese_alg_op_t ese_alg_ops[] = {
    { "ecdsa_p256",          "keygen", 0 },
    { "ecdsa_p256",          "sign",   0 },
    { "ecdsa_p256",          "verify", 0 },
    { "rsa3072",             "sign",   0 },
    { "rsa3072",             "verify", 0 },
    { "mldsa44",             "keygen", 0 },
    { "mldsa44",             "sign",   0 },
    { "mldsa44",             "verify", 0 },
    { "falcon512",           "keygen", ESE_N_SLOW },
    { "falcon512",           "sign",   0 },
    { "falcon512",           "verify", 0 },
    { "slhdsa_sha2_128s",    "keygen", ESE_N_SLOW },
    { "slhdsa_sha2_128s",    "sign",   ESE_N_SLOW },
    { "slhdsa_sha2_128s",    "verify", 0 },
    { "slhdsa_sha2_128f",    "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_sha2_128f",    "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_sha2_128f",    "verify", 0 },
    { "slhdsa_shake_128s",   "keygen", ESE_N_SLOW },
    { "slhdsa_shake_128s",   "sign",   ESE_N_SLOW },
    { "slhdsa_shake_128s",   "verify", 0 },
    { "slhdsa_shake_128f",   "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_shake_128f",   "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_shake_128f",   "verify", 0 },
    { "lms_h10",             "verify", 0 },
    { "lms_h15",             "verify", 0 },
    { "xmss_h10",            "verify", 0 },
    { "xmss_h16",            "verify", 0 },
    { "secp256r1",           "keygen", 0 },
    { "secp256r1",           "shared", 0 },
    { "x25519",              "keygen", 0 },
    { "x25519",              "shared", 0 },
    { "mlkem768",            "keygen", 0 },
    { "mlkem768",            "encap",  0 },
    { "mlkem768",            "decap",  0 },
#ifdef ESE_ALL_PQC_PARAMS
    { "mlkem512",            "keygen", 0 },
    { "mlkem512",            "encap",  0 },
    { "mlkem512",            "decap",  0 },
    { "mlkem1024",           "keygen", 0 },
    { "mlkem1024",           "encap",  0 },
    { "mlkem1024",           "decap",  0 },
    { "mldsa65",             "keygen", 0 },
    { "mldsa65",             "sign",   0 },
    { "mldsa65",             "verify", 0 },
    { "mldsa87",             "keygen", 0 },
    { "mldsa87",             "sign",   0 },
    { "mldsa87",             "verify", 0 },
    { "falcon1024",          "keygen", ESE_N_SLOW },
    { "falcon1024",          "sign",   0 },
    { "falcon1024",          "verify", 0 },
    { "slhdsa_sha2_192s",  "keygen", ESE_N_SLOW },
    { "slhdsa_sha2_192s",  "sign",   ESE_N_SLOW },
    { "slhdsa_sha2_192s",  "verify", 0 },
    { "slhdsa_sha2_192f",  "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_sha2_192f",  "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_sha2_192f",  "verify", 0 },
    { "slhdsa_sha2_256s",  "keygen", ESE_N_SLOW },
    { "slhdsa_sha2_256s",  "sign",   ESE_N_SLOW },
    { "slhdsa_sha2_256s",  "verify", 0 },
    { "slhdsa_sha2_256f",  "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_sha2_256f",  "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_sha2_256f",  "verify", 0 },
    { "slhdsa_shake_192s", "keygen", ESE_N_SLOW },
    { "slhdsa_shake_192s", "sign",   ESE_N_SLOW },
    { "slhdsa_shake_192s", "verify", 0 },
    { "slhdsa_shake_192f", "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_shake_192f", "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_shake_192f", "verify", 0 },
    { "slhdsa_shake_256s", "keygen", ESE_N_SLOW },
    { "slhdsa_shake_256s", "sign",   ESE_N_SLOW },
    { "slhdsa_shake_256s", "verify", 0 },
    { "slhdsa_shake_256f", "keygen", ESE_N_SLHDSA_F },
    { "slhdsa_shake_256f", "sign",   ESE_N_SLHDSA_F },
    { "slhdsa_shake_256f", "verify", 0 },
    { "lms_h10_w1",        "verify", 0 },
    { "lms_h10_w2",        "verify", 0 },
    { "lms_h10_w8",        "verify", 0 },
    { "lms_h20_w4",        "verify", 0 },
    { "lms_l2_h10_w4",     "verify", 0 },
    { "lms192_h10_w4",     "verify", 0 },
    { "xmss_h20",          "verify", 0 },
    { "xmssmt_h20_d2",     "verify", 0 },
    { "xmssmt_h40_d4",     "verify", 0 },
#endif
};
const int ese_alg_op_count = (int)(sizeof(ese_alg_ops) / sizeof(ese_alg_ops[0]));

static const struct {
    const char *name;
    int family;
    enum wc_LmsParm lms_parm;
    const char *xmss_parm;
    const unsigned char *pub;
    const unsigned int *pub_len;
    const unsigned char *sig;
    const unsigned int *sig_len;
} hbs_sets[] = {
    { "lms_h10", ALG_LMS, WC_LMS_PARM_L1_H10_W4, NULL,
      ese_lms_h10_pub, &ese_lms_h10_pub_len, ese_lms_h10_sig, &ese_lms_h10_sig_len },
    { "lms_h15", ALG_LMS, WC_LMS_PARM_L1_H15_W4, NULL,
      ese_lms_h15_pub, &ese_lms_h15_pub_len, ese_lms_h15_sig, &ese_lms_h15_sig_len },
    { "xmss_h10", ALG_XMSS, 0, "XMSS-SHA2_10_256",
      ese_xmss_h10_pub, &ese_xmss_h10_pub_len, ese_xmss_h10_sig,
      &ese_xmss_h10_sig_len },
    { "xmss_h16", ALG_XMSS, 0, "XMSS-SHA2_16_256",
      ese_xmss_h16_pub, &ese_xmss_h16_pub_len, ese_xmss_h16_sig,
      &ese_xmss_h16_sig_len },
};

struct ese_alg_state {
    int alg;
    int op;
    ese_hbs_vec_t hbs;
    int level;
    enum SlhDsaParam slh;
    WC_RNG rng;
    void *key;
    void *peer;
    unsigned char msg[ESE_BENCH_MSG_LEN];
    unsigned char hash[WC_SHA256_DIGEST_SIZE];
    unsigned char *sig;
    word32 sig_max;
    word32 sig_len;
    unsigned char ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    word32 ct_len;
    unsigned char ss[64];
    size_t heap_base;
};

int ese_alg_find(const char *alg, const char *op)
{
    int i;

    for (i = 0; i < ese_alg_op_count; i++) {
        if (strcmp(ese_alg_ops[i].alg, alg) == 0 &&
            strcmp(ese_alg_ops[i].op, op) == 0) {
            return i;
        }
    }
    return -1;
}

int ese_alg_default_n(int idx)
{
    return ese_alg_ops[idx].n != 0 ? ese_alg_ops[idx].n : ESE_N_DEFAULT;
}

static int classify(const char *alg, int *family, enum SlhDsaParam *slh,
                    ese_hbs_vec_t *hbs, int *level)
{
    static const struct { const char *name; int family; int level; } map[] = {
        { "ecdsa_p256", ALG_ECDSA, 0 }, { "rsa3072", ALG_RSA, 0 },
        { "mldsa44", ALG_MLDSA, WC_ML_DSA_44 }, { "falcon512", ALG_FALCON, 1 },
        { "secp256r1", ALG_ECDH, 0 }, { "x25519", ALG_X25519, 0 },
        { "mlkem768", ALG_MLKEM, WC_ML_KEM_768 },
#ifdef ESE_ALL_PQC_PARAMS
        { "mlkem512", ALG_MLKEM, WC_ML_KEM_512 },
        { "mlkem1024", ALG_MLKEM, WC_ML_KEM_1024 },
        { "mldsa65", ALG_MLDSA, WC_ML_DSA_65 },
        { "mldsa87", ALG_MLDSA, WC_ML_DSA_87 },
        { "falcon1024", ALG_FALCON, 5 },
#endif
    };
    size_t i;

    for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (strcmp(alg, map[i].name) == 0) {
            *family = map[i].family;
            *level = map[i].level;
            return 0;
        }
    }
    for (i = 0; i < sizeof(hbs_sets) / sizeof(hbs_sets[0]); i++) {
        if (strcmp(alg, hbs_sets[i].name) == 0) {
            *family = hbs_sets[i].family;
            hbs->lms_parm = hbs_sets[i].lms_parm;
            hbs->xmss_parm = hbs_sets[i].xmss_parm;
            hbs->pub = hbs_sets[i].pub;
            hbs->pub_len = *hbs_sets[i].pub_len;
            hbs->sig = hbs_sets[i].sig;
            hbs->sig_len = *hbs_sets[i].sig_len;
            return 0;
        }
    }
#ifdef ESE_ALL_PQC_PARAMS
    for (i = 0; i < (size_t)ese_hbs_vec_count; i++) {
        if (strcmp(alg, ese_hbs_vecs[i].name) == 0) {
            *family = ese_hbs_vecs[i].xmss_parm != NULL ? ALG_XMSS : ALG_LMS;
            *hbs = ese_hbs_vecs[i];
            return 0;
        }
    }
#endif
    *family = ALG_SLH;
    if (strcmp(alg, "slhdsa_sha2_128s") == 0)       *slh = SLHDSA_SHA2_128S;
    else if (strcmp(alg, "slhdsa_sha2_128f") == 0)  *slh = SLHDSA_SHA2_128F;
    else if (strcmp(alg, "slhdsa_shake_128s") == 0) *slh = SLHDSA_SHAKE128S;
    else if (strcmp(alg, "slhdsa_shake_128f") == 0) *slh = SLHDSA_SHAKE128F;
#ifdef ESE_ALL_PQC_PARAMS
    else if (strcmp(alg, "slhdsa_sha2_192s") == 0)  *slh = SLHDSA_SHA2_192S;
    else if (strcmp(alg, "slhdsa_sha2_192f") == 0)  *slh = SLHDSA_SHA2_192F;
    else if (strcmp(alg, "slhdsa_sha2_256s") == 0)  *slh = SLHDSA_SHA2_256S;
    else if (strcmp(alg, "slhdsa_sha2_256f") == 0)  *slh = SLHDSA_SHA2_256F;
    else if (strcmp(alg, "slhdsa_shake_192s") == 0) *slh = SLHDSA_SHAKE192S;
    else if (strcmp(alg, "slhdsa_shake_192f") == 0) *slh = SLHDSA_SHAKE192F;
    else if (strcmp(alg, "slhdsa_shake_256s") == 0) *slh = SLHDSA_SHAKE256S;
    else if (strcmp(alg, "slhdsa_shake_256f") == 0) *slh = SLHDSA_SHAKE256F;
#endif
    else return BAD_FUNC_ARG;
    return 0;
}

static int op_code(const char *op)
{
    static const char *names[] = { "keygen", "sign", "verify", "shared",
                                   "encap", "decap" };
    int i;

    for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        if (strcmp(op, names[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/* Creates a key of the state's family; the ops free it the same way. */
static int key_new(ese_alg_state_t *st, void **out)
{
    int ret;

    switch (st->alg) {
    case ALG_ECDSA:
    case ALG_ECDH: {
        ecc_key *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_ecc_init_ex(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_ecc_make_key_ex(&st->rng, 32, k, ECC_SECP256R1);
        if (ret == 0) ret = wc_ecc_set_rng(k, &st->rng);
        *out = k;
        return ret;
    }
    case ALG_X25519: {
        curve25519_key *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_curve25519_init_ex(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_curve25519_make_key(&st->rng, 32, k);
        *out = k;
        return ret;
    }
    case ALG_MLKEM: {
        MlKemKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_MlKemKey_Init(k, st->level, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_MlKemKey_MakeKey(k, &st->rng);
        *out = k;
        return ret;
    }
    case ALG_MLDSA: {
        wc_MlDsaKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_MlDsaKey_Init(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_MlDsaKey_SetParams(k, (byte)st->level);
        if (ret == 0) ret = wc_MlDsaKey_MakeKey(k, &st->rng);
        *out = k;
        return ret;
    }
    case ALG_FALCON: {
        falcon_key *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_falcon_init_ex(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_falcon_set_level(k, (byte)st->level);
        if (ret == 0) ret = wc_falcon_make_key(k, &st->rng);
        *out = k;
        return ret;
    }
    case ALG_SLH: {
        SlhDsaKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        ret = wc_SlhDsaKey_Init(k, st->slh, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_SlhDsaKey_MakeKey(k, &st->rng);
        *out = k;
        return ret;
    }
    default:
        return NOT_COMPILED_IN;
    }
}

static void key_free(ese_alg_state_t *st, void *key)
{
    if (key == NULL) {
        return;
    }
    switch (st->alg) {
    case ALG_ECDSA:
    case ALG_ECDH:   wc_ecc_free(key); break;
    case ALG_RSA:    wc_FreeRsaKey(key); break;
    case ALG_X25519: wc_curve25519_free(key); break;
    case ALG_MLKEM:  wc_MlKemKey_Free(key); break;
    case ALG_MLDSA:  wc_MlDsaKey_Free(key); break;
    case ALG_FALCON: wc_falcon_free(key); break;
    case ALG_SLH:    wc_SlhDsaKey_Free(key); break;
    case ALG_LMS:    wc_LmsKey_Free(key); break;
    case ALG_XMSS:   wc_XmssKey_Free(key); break;
    default: break;
    }
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

static int do_sign(ese_alg_state_t *st)
{
    st->sig_len = st->sig_max;
    switch (st->alg) {
    case ALG_ECDSA: {
        int ret = wc_Sha256Hash_ex(st->msg, sizeof(st->msg), st->hash, NULL,
                                ESE_DEVID);
        if (ret == 0) {
            ret = wc_ecc_sign_hash(st->hash, sizeof(st->hash), st->sig,
                                   &st->sig_len, &st->rng, st->key);
        }
        return ret;
    }
    case ALG_RSA: {
        int ret = wc_Sha256Hash_ex(st->msg, sizeof(st->msg), st->hash, NULL,
                                ESE_DEVID);
        if (ret == 0) {
            ret = wc_RsaPSS_Sign(st->hash, sizeof(st->hash), st->sig, st->sig_max,
                                 WC_HASH_TYPE_SHA256, WC_MGF1SHA256, st->key,
                                 &st->rng);
        }
        if (ret > 0) {
            st->sig_len = (word32)ret;
            ret = 0;
        }
        return ret;
    }
    case ALG_MLDSA:
        return wc_MlDsaKey_SignCtx(st->key, NULL, 0, st->sig, &st->sig_len,
                                   st->msg, sizeof(st->msg), &st->rng);
    case ALG_FALCON:
        return wc_falcon_sign_msg(st->msg, sizeof(st->msg), st->sig,
                                  &st->sig_len, st->key, &st->rng);
    case ALG_SLH:
        return wc_SlhDsaKey_Sign(st->key, NULL, 0, st->msg, sizeof(st->msg),
                                 st->sig, &st->sig_len, &st->rng);
    default:
        return NOT_COMPILED_IN;
    }
}

static int do_verify(ese_alg_state_t *st)
{
    int res = 0;
    int ret;

    switch (st->alg) {
    case ALG_ECDSA:
        ret = wc_Sha256Hash_ex(st->msg, sizeof(st->msg), st->hash, NULL,
                                ESE_DEVID);
        if (ret == 0) {
            ret = wc_ecc_verify_hash(st->sig, st->sig_len, st->hash,
                                     sizeof(st->hash), &res, st->key);
        }
        break;
    case ALG_RSA: {
        unsigned char out[512];
        ret = wc_Sha256Hash_ex(st->msg, sizeof(st->msg), st->hash, NULL,
                                ESE_DEVID);
        if (ret == 0) {
            ret = wc_RsaPSS_VerifyCheck(st->sig, st->sig_len, out, sizeof(out),
                                        st->hash, sizeof(st->hash),
                                        WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                        st->key);
        }
        return ret < 0 ? ret : 0;
    }
    case ALG_MLDSA:
        ret = wc_MlDsaKey_VerifyCtx(st->key, st->sig, st->sig_len, NULL, 0,
                                    st->msg, sizeof(st->msg), &res);
        break;
    case ALG_FALCON:
        ret = wc_falcon_verify_msg(st->sig, st->sig_len, st->msg,
                                   sizeof(st->msg), &res, st->key);
        break;
    case ALG_SLH:
        return wc_SlhDsaKey_Verify(st->key, NULL, 0, st->msg, sizeof(st->msg),
                                   st->sig, st->sig_len);
    case ALG_LMS:
        return wc_LmsKey_Verify(st->key, st->hbs.sig, st->hbs.sig_len,
                                st->msg, (int)sizeof(st->msg));
    case ALG_XMSS:
        return wc_XmssKey_Verify(st->key, st->hbs.sig, st->hbs.sig_len,
                                 st->msg, (int)sizeof(st->msg));
    default:
        return NOT_COMPILED_IN;
    }
    if (ret == 0 && res != 1) {
        ret = SIG_VERIFY_E;
    }
    return ret;
}

static int do_shared(ese_alg_state_t *st)
{
    word32 len = sizeof(st->ss);

    if (st->alg == ALG_X25519) {
        return wc_curve25519_shared_secret_ex(st->key, st->peer, st->ss, &len,
                                              EC25519_LITTLE_ENDIAN);
    }
    return wc_ecc_shared_secret(st->key, st->peer, st->ss, &len);
}

static int load_rsa(ese_alg_state_t *st)
{
    const ese_chain_certs_t *cc = &ese_chain_certs[ese_chain_find("rsa3072")];
    RsaKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    word32 idx = 0;
    int ret;

    if (k == NULL) {
        return MEMORY_E;
    }
    st->key = k;
    ret = wc_InitRsaKey_ex(k, NULL, ESE_DEVID);
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(cc->server_key, &idx, k,
                                     cc->server_key_len);
    }
    if (ret == 0) {
        ret = wc_RsaSetRNG(k, &st->rng);
    }
    return ret;
}

static int load_hbs(ese_alg_state_t *st)
{
    const unsigned char *pub = st->hbs.pub;
    word32 pub_len = st->hbs.pub_len;
    int ret;

    if (st->alg == ALG_LMS) {
        LmsKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        st->key = k;
        ret = wc_LmsKey_Init(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_LmsKey_SetLmsParm(k,
                                (enum wc_LmsParm)st->hbs.lms_parm);
        if (ret == 0) ret = wc_LmsKey_ImportPubRaw(k, pub, pub_len);
    }
    else {
        XmssKey *k = (void *)XMALLOC(sizeof(*k), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (k == NULL) return MEMORY_E;
        st->key = k;
        ret = wc_XmssKey_Init(k, NULL, ESE_DEVID);
        if (ret == 0) ret = wc_XmssKey_SetParamStr(k, st->hbs.xmss_parm);
        if (ret == 0) ret = wc_XmssKey_ImportPubRaw(k, pub, pub_len);
    }
    return ret;
}

int ese_alg_setup(int idx, ese_alg_state_t **out)
{
    ese_alg_state_t *st;
    int ret;

    *out = NULL;
    if (idx < 0 || idx >= ese_alg_op_count) {
        return BAD_FUNC_ARG;
    }
    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        return MEMORY_E;
    }
    *out = st;
    st->op = op_code(ese_alg_ops[idx].op);
    ret = classify(ese_alg_ops[idx].alg, &st->alg, &st->slh, &st->hbs,
                   &st->level);
    if (ret == 0) {
        ret = wc_InitRng_ex(&st->rng, NULL, ESE_DEVID);
    }
    if (ret != 0) {
        return ret;
    }
    st->sig_max = st->alg == ALG_SLH ? WC_SLHDSA_MAX_SIG_LEN : SIG_MAX;
    st->sig = malloc(st->sig_max);
    if (st->sig == NULL) {
        return MEMORY_E;
    }
    st->heap_base = ese_heap_cur();
    ese_bench_msg(st->msg);

    if (st->alg == ALG_RSA) {
        ret = load_rsa(st);
    }
    else if (st->alg == ALG_LMS || st->alg == ALG_XMSS) {
        ret = load_hbs(st);
    }
    else if (st->op != OP_KEYGEN) {
        ret = key_new(st, &st->key);
    }
    if (ret == 0 && (st->op == OP_SHARED)) {
        ret = key_new(st, &st->peer);
    }
    if (ret == 0 && st->op == OP_VERIFY && st->alg != ALG_LMS &&
        st->alg != ALG_XMSS) {
        ret = do_sign(st);
    }
    if (ret == 0 && st->op == OP_DECAP) {
        ret = wc_MlKemKey_CipherTextSize(st->key, &st->ct_len);
    }
    if (ret == 0 && st->op == OP_DECAP) {
        ret = wc_MlKemKey_Encapsulate(st->key, st->ct, st->ss, &st->rng);
    }
    return ret;
}

static int run_one(ese_alg_state_t *st)
{
    void *k = NULL;
    int ret;

    switch (st->op) {
    case OP_KEYGEN:
        ret = key_new(st, &k);
        key_free(st, k);
        return ret;
    case OP_SIGN:
        return do_sign(st);
    case OP_VERIFY:
        return do_verify(st);
    case OP_SHARED:
        return do_shared(st);
    case OP_ENCAP:
        return wc_MlKemKey_Encapsulate(st->key, st->ct, st->ss, &st->rng);
    case OP_DECAP:
        return wc_MlKemKey_Decapsulate(st->key, st->ss, st->ct,
                                       st->ct_len);
    default:
        return BAD_FUNC_ARG;
    }
}

void ese_alg_run(ese_alg_state_t *st, int n, ese_alg_sample_t *out)
{
    ese_heap_stats_t hs;
    uint64_t t0;
    int i;

    for (i = 0; i < n; i++) {
        ese_heap_window_start();
        t0 = ese_now_ns();
        out[i].status = run_one(st);
        out[i].ns = ese_now_ns() - t0;
        ese_heap_window_get(&hs);
        out[i].heap_peak = hs.peak;
        out[i].heap_total = hs.total;
        out[i].heap_allocs = hs.allocs;
    }
}

uint32_t ese_alg_key_held(const ese_alg_state_t *st)
{
    size_t cur = ese_heap_cur();

    return cur > st->heap_base ? (uint32_t)(cur - st->heap_base) : 0;
}

void ese_alg_teardown(ese_alg_state_t *st)
{
    if (st == NULL) {
        return;
    }
    key_free(st, st->key);
    key_free(st, st->peer);
    wc_FreeRng(&st->rng);
    free(st->sig);
    free(st);
}
