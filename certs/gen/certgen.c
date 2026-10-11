/* Generates the root/intermediate/leaf chains for every entry in ese_chains[]. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "ese_algs.h"

#define DER_MAX (64 * 1024)
#define STATE_MAX (64 * 1024)

enum { LVL_ROOT, LVL_INT, LVL_SERVER, LVL_CLIENT, LVL_COUNT };
static const char *lvl_name[LVL_COUNT] = { "root", "int", "server", "client" };

typedef struct {
    ese_sig_t alg;
    int key_type;
    int ctc;
    void *key;
    byte state[STATE_MAX];
    word32 state_sz;
    byte skid[WC_SHA_DIGEST_SIZE];
    byte pub[DER_MAX];
    int pub_sz;
    byte cert[DER_MAX];
    int cert_sz;
    byte priv[DER_MAX];
    int priv_sz;
} gkey_t;

static WC_RNG rng;

#define CHECK(x) do { int _r = (x); if (_r < 0) { \
    fprintf(stderr, "%s:%d: %s = %d (%s)\n", __FILE__, __LINE__, #x, _r, \
            wc_GetErrorString(_r)); exit(1); } } while (0)

static int lms_write(const byte *priv, word32 sz, void *ctx)
{
    gkey_t *k = (gkey_t *)ctx;

    if (sz > sizeof(k->state)) {
        return WC_LMS_RC_WRITE_FAIL;
    }
    memcpy(k->state, priv, sz);
    k->state_sz = sz;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int lms_read(byte *priv, word32 sz, void *ctx)
{
    gkey_t *k = (gkey_t *)ctx;

    if (sz != k->state_sz) {
        return WC_LMS_RC_READ_FAIL;
    }
    memcpy(priv, k->state, sz);
    return WC_LMS_RC_READ_TO_MEMORY;
}

static enum wc_XmssRc xmss_write(const byte *priv, word32 sz, void *ctx)
{
    gkey_t *k = (gkey_t *)ctx;

    if (sz > sizeof(k->state)) {
        return WC_XMSS_RC_WRITE_FAIL;
    }
    memcpy(k->state, priv, sz);
    k->state_sz = sz;
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}

static enum wc_XmssRc xmss_read(byte *priv, word32 sz, void *ctx)
{
    gkey_t *k = (gkey_t *)ctx;

    if (sz != k->state_sz) {
        return WC_XMSS_RC_READ_FAIL;
    }
    memcpy(priv, k->state, sz);
    return WC_XMSS_RC_READ_TO_MEMORY;
}

static enum SlhDsaParam slh_param(ese_sig_t a)
{
    switch (a) {
    case ESE_SIG_SLHDSA_SHA2_128S:  return SLHDSA_SHA2_128S;
    case ESE_SIG_SLHDSA_SHA2_128F:  return SLHDSA_SHA2_128F;
    case ESE_SIG_SLHDSA_SHAKE_128S: return SLHDSA_SHAKE128S;
    default:                        return SLHDSA_SHAKE128F;
    }
}

static void key_gen(gkey_t *k, ese_sig_t alg, int lvl)
{
    memset(k, 0, sizeof(*k));
    k->alg = alg;

    switch (alg) {
    case ESE_SIG_ECDSA_P256: {
        ecc_key *e = calloc(1, sizeof(*e));
        CHECK(wc_ecc_init(e));
        CHECK(wc_ecc_make_key_ex(&rng, 32, e, ECC_SECP256R1));
        k->key = e; k->key_type = ECC_TYPE; k->ctc = CTC_SHA256wECDSA;
        k->pub_sz = wc_EccPublicKeyToDer(e, k->pub, DER_MAX, 1);
        k->priv_sz = wc_EccKeyToDer(e, k->priv, DER_MAX);
        break;
    }
    case ESE_SIG_RSA3072: {
        RsaKey *r = calloc(1, sizeof(*r));
        CHECK(wc_InitRsaKey(r, NULL));
        CHECK(wc_MakeRsaKey(r, 3072, WC_RSA_EXPONENT, &rng));
        CHECK(wc_RsaSetRNG(r, &rng));
        k->key = r; k->key_type = RSA_TYPE; k->ctc = CTC_SHA256wRSA;
        k->pub_sz = wc_RsaKeyToPublicDer(r, k->pub, DER_MAX);
        k->priv_sz = wc_RsaKeyToDer(r, k->priv, DER_MAX);
        break;
    }
    case ESE_SIG_MLDSA44: {
        wc_MlDsaKey *m = calloc(1, sizeof(*m));
        CHECK(wc_MlDsaKey_Init(m, NULL, INVALID_DEVID));
        CHECK(wc_MlDsaKey_SetParams(m, WC_ML_DSA_44));
        CHECK(wc_MlDsaKey_MakeKey(m, &rng));
        k->key = m; k->key_type = ML_DSA_44_TYPE; k->ctc = CTC_ML_DSA_44;
        k->pub_sz = wc_MlDsaKey_PublicKeyToDer(m, k->pub, DER_MAX, 1);
        k->priv_sz = wc_MlDsaKey_KeyToDer(m, k->priv, DER_MAX);
        break;
    }
    case ESE_SIG_FALCON512: {
        falcon_key *f = calloc(1, sizeof(*f));
        CHECK(wc_falcon_init(f));
        CHECK(wc_falcon_set_level(f, 1));
        CHECK(wc_falcon_make_key(f, &rng));
        k->key = f; k->key_type = FALCON_LEVEL1_TYPE; k->ctc = CTC_FALCON_LEVEL1;
        k->pub_sz = wc_Falcon_PublicKeyToDer(f, k->pub, DER_MAX, 1);
        k->priv_sz = wc_Falcon_KeyToDer(f, k->priv, DER_MAX);
        break;
    }
    case ESE_SIG_SLHDSA_SHA2_128S:
    case ESE_SIG_SLHDSA_SHA2_128F:
    case ESE_SIG_SLHDSA_SHAKE_128S:
    case ESE_SIG_SLHDSA_SHAKE_128F: {
        static const int types[] = { SLH_DSA_SHA2_128S_TYPE,
            SLH_DSA_SHA2_128F_TYPE, SLH_DSA_SHAKE_128S_TYPE,
            SLH_DSA_SHAKE_128F_TYPE };
        static const int ctcs[] = { CTC_SLH_DSA_SHA2_128S,
            CTC_SLH_DSA_SHA2_128F, CTC_SLH_DSA_SHAKE_128S,
            CTC_SLH_DSA_SHAKE_128F };
        int i = (int)alg - (int)ESE_SIG_SLHDSA_SHA2_128S;
        SlhDsaKey *s = calloc(1, sizeof(*s));
        CHECK(wc_SlhDsaKey_Init(s, slh_param(alg), NULL, INVALID_DEVID));
        CHECK(wc_SlhDsaKey_MakeKey(s, &rng));
        k->key = s; k->key_type = types[i]; k->ctc = ctcs[i];
        k->pub_sz = wc_SlhDsaKey_PublicKeyToDer(s, k->pub, DER_MAX, 1);
        k->priv_sz = wc_SlhDsaKey_KeyToDer(s, k->priv, DER_MAX);
        break;
    }
    case ESE_SIG_LMS: {
        LmsKey *l = calloc(1, sizeof(*l));
        CHECK(wc_LmsKey_Init(l, NULL, INVALID_DEVID));
        CHECK(wc_LmsKey_SetLmsParm(l, lvl == LVL_ROOT ?
            WC_LMS_PARM_L1_H10_W4 : WC_LMS_PARM_L1_H15_W4));
        CHECK(wc_LmsKey_SetWriteCb(l, lms_write));
        CHECK(wc_LmsKey_SetReadCb(l, lms_read));
        CHECK(wc_LmsKey_SetContext(l, k));
        CHECK(wc_LmsKey_MakeKey(l, &rng));
        k->key = l; k->key_type = LMS_TYPE; k->ctc = CTC_HSS_LMS;
        k->pub_sz = wc_LmsKey_PublicKeyToDer(l, k->pub, DER_MAX, 1);
        break;
    }
    case ESE_SIG_XMSS: {
        XmssKey *x = calloc(1, sizeof(*x));
        CHECK(wc_XmssKey_Init(x, NULL, INVALID_DEVID));
        CHECK(wc_XmssKey_SetParamStr(x, lvl == LVL_ROOT ?
            "XMSS-SHA2_10_256" : "XMSS-SHA2_16_256"));
        CHECK(wc_XmssKey_SetWriteCb(x, xmss_write));
        CHECK(wc_XmssKey_SetReadCb(x, xmss_read));
        CHECK(wc_XmssKey_SetContext(x, k));
        CHECK(wc_XmssKey_MakeKey(x, &rng));
        k->key = x; k->key_type = XMSS_TYPE; k->ctc = CTC_XMSS;
        k->pub_sz = wc_XmssKey_PublicKeyToDer(x, k->pub, DER_MAX, 1);
        break;
    }
    default:
        fprintf(stderr, "unknown alg %d\n", alg);
        exit(1);
    }
    CHECK(k->pub_sz);
    CHECK(k->priv_sz);
}

static void key_free(gkey_t *k)
{
    switch (k->alg) {
    case ESE_SIG_ECDSA_P256: wc_ecc_free(k->key); break;
    case ESE_SIG_RSA3072:    wc_FreeRsaKey(k->key); break;
    case ESE_SIG_MLDSA44:    wc_MlDsaKey_Free(k->key); break;
    case ESE_SIG_FALCON512:  wc_falcon_free(k->key); break;
    case ESE_SIG_LMS:        wc_LmsKey_Free(k->key); break;
    case ESE_SIG_XMSS:       wc_XmssKey_Free(k->key); break;
    default:                 wc_SlhDsaKey_Free(k->key); break;
    }
    free(k->key);
}

/* Reads one DER header at *p; returns the content length and advances *p. */
static int der_hdr(const byte **p, const byte *end, byte *tag)
{
    int len;
    int n;

    if (*p + 2 > end) {
        return -1;
    }
    *tag = *(*p)++;
    len = *(*p)++;
    if (len & 0x80) {
        n = len & 0x7f;
        len = 0;
        while (n-- > 0) {
            len = (len << 8) | *(*p)++;
        }
    }
    return len;
}

/* RFC 5280 method 1: SHA-1 of the subjectPublicKey BIT STRING contents. */
static void set_skid(gkey_t *k)
{
    const byte *p = k->pub;
    const byte *end = k->pub + k->pub_sz;
    byte tag;
    int len;

    der_hdr(&p, end, &tag);
    len = der_hdr(&p, end, &tag);
    p += len;
    len = der_hdr(&p, end, &tag);
    if (tag != 0x03 || len < 2) {
        fprintf(stderr, "bad SPKI for %s\n", ese_sigs[k->alg].name);
        exit(1);
    }
    CHECK(wc_ShaHash(p + 1, (word32)len - 1, k->skid));
}

static int put_hdr(byte *out, byte tag, int len)
{
    out[0] = tag;
    if (len < 0x80) {
        out[1] = (byte)len;
        return 2;
    }
    out[1] = 0x81;
    out[2] = (byte)len;
    return 3;
}

static int make_crl_dp(byte *out, const char *url)
{
    int ul = (int)strlen(url);
    int l4 = 2 + ul;
    int l3 = 2 + l4;
    int l2 = 2 + l3;
    int l1 = 2 + l2;
    int o = 0;

    o += put_hdr(out + o, 0x30, l1);
    o += put_hdr(out + o, 0x30, l2);
    o += put_hdr(out + o, 0xA0, l3);
    o += put_hdr(out + o, 0xA0, l4);
    o += put_hdr(out + o, 0x86, ul);
    memcpy(out + o, url, (size_t)ul);
    return o + ul;
}

static int make_san(byte *out, const char *dns, const byte *ip4)
{
    int dl = (int)strlen(dns);
    int inner = 2 + dl + (ip4 != NULL ? 6 : 0);
    int o = put_hdr(out, 0x30, inner);

    o += put_hdr(out + o, 0x82, dl);
    memcpy(out + o, dns, (size_t)dl);
    o += dl;
    if (ip4 != NULL) {
        o += put_hdr(out + o, 0x87, 4);
        memcpy(out + o, ip4, 4);
        o += 4;
    }
    return o;
}

static void set_name(CertName *n, const char *cn)
{
    strncpy(n->country, "DE", CTC_NAME_SIZE - 1);
    strncpy(n->org, "ESE 2026 PQC Benchmark", CTC_NAME_SIZE - 1);
    strncpy(n->unit, "Industrial IoT", CTC_NAME_SIZE - 1);
    strncpy(n->commonName, cn, CTC_NAME_SIZE - 1);
}

static void set_date(byte *dst, int *dst_sz, const char *utc)
{
    dst[0] = 0x17; /* UTCTime */
    dst[1] = 13;
    memcpy(dst + 2, utc, 13);
    *dst_sz = 15;
}

static void make_cert(int lvl, gkey_t *subj, gkey_t *iss)
{
    static const byte ip[4] = { 192, 168, 1, 10 };
    static const char *cn[LVL_COUNT] = { "ESE Root CA", "ESE Issuing CA",
        "ese-server", "ese-client-01" };
    static const char *not_after[LVL_COUNT] = { "460101000000Z",
        "360101000000Z", "310101000000Z", "310101000000Z" };
    Cert *c = calloc(1, sizeof(*c));
    int sz;

    CHECK(wc_InitCert(c));
    c->version = 2;
    c->serialSz = 16;
    memset(c->serial, 0x5E, sizeof(c->serial));
    c->serial[0] = 0x3E;
    c->serial[1] = (byte)lvl;
    set_name(&c->subject, cn[lvl]);
    set_date(c->beforeDate, &c->beforeDateSz, "260101000000Z");
    set_date(c->afterDate, &c->afterDateSz, not_after[lvl]);

    c->basicConstSet = 1;
    c->basicConstCrit = 1;
    if (lvl == LVL_ROOT || lvl == LVL_INT) {
        c->isCA = 1;
        if (lvl == LVL_INT) {
            c->pathLen = 0;
            c->pathLenSet = 1;
        }
        CHECK(wc_SetKeyUsage(c, "keyCertSign,cRLSign"));
    }
    else {
        CHECK(wc_SetKeyUsage(c, "digitalSignature"));
        CHECK(wc_SetExtKeyUsage(c,
            lvl == LVL_SERVER ? "serverAuth" : "clientAuth"));
        c->altNamesSz = make_san(c->altNames,
            lvl == LVL_SERVER ? "ese-server.local" : "ese-client-01.local",
            lvl == LVL_SERVER ? ip : NULL);
    }
    if (lvl == LVL_INT) {
        c->crlInfoSz = make_crl_dp(c->crlInfo,
            "http://pki.ese-demo.example/root.crl");
    }
    else if (lvl != LVL_ROOT) {
        c->crlInfoSz = make_crl_dp(c->crlInfo,
            "http://pki.ese-demo.example/issuing.crl");
    }

    memcpy(c->skid, subj->skid, sizeof(subj->skid));
    c->skidSz = (int)sizeof(subj->skid);
    memcpy(c->akid, iss->skid, sizeof(iss->skid));
    c->akidSz = (int)sizeof(iss->skid);

    if (lvl == LVL_ROOT) {
        set_name(&c->issuer, cn[lvl]);
        c->selfSigned = 1;
    }
    else {
        CHECK(wc_SetIssuerBuffer(c, iss->cert, iss->cert_sz));
    }
    c->sigType = iss->ctc;

    CHECK(wc_MakeCert_ex(c, subj->cert, DER_MAX, subj->key_type, subj->key,
                         &rng));
    sz = wc_SignCert_ex(c->bodySz, c->sigType, subj->cert, DER_MAX,
                        iss->key_type, iss->key, &rng);
    CHECK(sz);
    subj->cert_sz = sz;
    free(c);
}

static void write_file(const char *dir, const char *name, const byte *b,
                       int sz)
{
    char path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (f == NULL || fwrite(b, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "write %s failed\n", path);
        exit(1);
    }
    fclose(f);
}

static void emit_array_q(FILE *f, const char *qual, const char *sym,
                         const byte *b, int sz)
{
    int i;

    fprintf(f, "%sconst unsigned char %s[%d] = {", qual, sym, sz);
    for (i = 0; i < sz; i++) {
        fprintf(f, "%s0x%02x,", (i % 16) == 0 ? "\n    " : " ", b[i]);
    }
    fprintf(f, "\n};\n\n");
}

static void emit_array(FILE *f, const char *sym, const byte *b, int sz)
{
    emit_array_q(f, "static ", sym, b, sz);
}

static void emit_public(FILE *f, const char *sym, const byte *b, word32 sz)
{
    emit_array_q(f, "", sym, b, (int)sz);
    fprintf(f, "const unsigned int %s_len = %u;\n\n", sym, sz);
}

/* Signs ese_bench_msg() with a stateful CA key for the DUT verify benchmark. */
static void emit_hbs_vector(FILE *f, gkey_t *k, const char *pfx)
{
    byte msg[ESE_BENCH_MSG_LEN];
    byte pub[128];
    byte *sig = malloc(DER_MAX);
    word32 pub_sz = sizeof(pub);
    word32 sig_sz = DER_MAX;
    char sym[64];

    ese_bench_msg(msg);
    if (k->alg == ESE_SIG_LMS) {
        CHECK(wc_LmsKey_Sign(k->key, sig, &sig_sz, msg, (int)sizeof(msg)));
        CHECK(wc_LmsKey_ExportPubRaw(k->key, pub, &pub_sz));
    }
    else {
        CHECK(wc_XmssKey_Sign(k->key, sig, &sig_sz, msg, (int)sizeof(msg)));
        CHECK(wc_XmssKey_ExportPubRaw(k->key, pub, &pub_sz));
    }
    snprintf(sym, sizeof(sym), "%s_pub", pfx);
    emit_public(f, sym, pub, pub_sz);
    snprintf(sym, sizeof(sym), "%s_sig", pfx);
    emit_public(f, sym, sig, sig_sz);
    free(sig);
}

static void verify_chain(gkey_t *k)
{
    WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew();
    int i;

    CHECK(wolfSSL_CertManagerLoadCABuffer(cm, k[LVL_ROOT].cert,
        k[LVL_ROOT].cert_sz, WOLFSSL_FILETYPE_ASN1));
    CHECK(wolfSSL_CertManagerVerifyBuffer(cm, k[LVL_INT].cert,
        k[LVL_INT].cert_sz, WOLFSSL_FILETYPE_ASN1));
    CHECK(wolfSSL_CertManagerLoadCABuffer(cm, k[LVL_INT].cert,
        k[LVL_INT].cert_sz, WOLFSSL_FILETYPE_ASN1));
    for (i = LVL_SERVER; i <= LVL_CLIENT; i++) {
        CHECK(wolfSSL_CertManagerVerifyBuffer(cm, k[i].cert, k[i].cert_sz,
            WOLFSSL_FILETYPE_ASN1));
    }
    wolfSSL_CertManagerFree(cm);
}

int main(int argc, char **argv)
{
    const char *out = argc > 1 ? argv[1] : "certs/out";
    char dir[512];
    char path[512];
    char sym[128];
    FILE *src;
    FILE *sizes;
    gkey_t *k = calloc(LVL_COUNT, sizeof(gkey_t));
    int c;
    int l;
    int lms_done = 0;
    int xmss_done = 0;

    CHECK(wolfSSL_Init());
    CHECK(wc_InitRng(&rng));
    mkdir(out, 0755);

    snprintf(path, sizeof(path), "%s/ese_certs_data.c", out);
    src = fopen(path, "w");
    snprintf(path, sizeof(path), "%s/sizes.csv", out);
    sizes = fopen(path, "w");
    if (src == NULL || sizes == NULL) {
        fprintf(stderr, "cannot open outputs in %s\n", out);
        return 1;
    }
    fprintf(src, "/* Generated by certs/gen/certgen.c; do not edit. */\n"
                 "#include \"ese_certs.h\"\n\n");
    fprintf(sizes, "chain,level,alg,signer_alg,cert_bytes,spki_bytes,"
                   "privkey_bytes\n");

    for (c = 0; c < ese_chain_count; c++) {
        const ese_chain_t *ch = &ese_chains[c];

        printf("%-24s", ch->name);
        fflush(stdout);
        for (l = 0; l < LVL_COUNT; l++) {
            key_gen(&k[l], l <= LVL_INT ? ch->ca : ch->leaf, l);
            set_skid(&k[l]);
        }
        make_cert(LVL_ROOT, &k[LVL_ROOT], &k[LVL_ROOT]);
        make_cert(LVL_INT, &k[LVL_INT], &k[LVL_ROOT]);
        make_cert(LVL_SERVER, &k[LVL_SERVER], &k[LVL_INT]);
        make_cert(LVL_CLIENT, &k[LVL_CLIENT], &k[LVL_INT]);
        verify_chain(k);
        if (ch->ca == ESE_SIG_LMS && !lms_done) {
            emit_hbs_vector(src, &k[LVL_ROOT], "ese_lms_h10");
            emit_hbs_vector(src, &k[LVL_INT], "ese_lms_h15");
            lms_done = 1;
        }
        if (ch->ca == ESE_SIG_XMSS && !xmss_done) {
            emit_hbs_vector(src, &k[LVL_ROOT], "ese_xmss_h10");
            emit_hbs_vector(src, &k[LVL_INT], "ese_xmss_h16");
            xmss_done = 1;
        }

        snprintf(dir, sizeof(dir), "%s/%s", out, ch->name);
        mkdir(dir, 0755);
        for (l = 0; l < LVL_COUNT; l++) {
            snprintf(path, sizeof(path), "%s.der", lvl_name[l]);
            write_file(dir, path, k[l].cert, k[l].cert_sz);
            snprintf(sym, sizeof(sym), "c%d_%s", c, lvl_name[l]);
            emit_array(src, sym, k[l].cert, k[l].cert_sz);
            if (l >= LVL_SERVER) {
                snprintf(path, sizeof(path), "%s-key.der", lvl_name[l]);
                write_file(dir, path, k[l].priv, k[l].priv_sz);
                snprintf(sym, sizeof(sym), "c%d_%s_key", c, lvl_name[l]);
                emit_array(src, sym, k[l].priv, k[l].priv_sz);
            }
            fprintf(sizes, "%s,%s,%s,%s,%d,%d,%d\n", ch->name, lvl_name[l],
                ese_sigs[k[l].alg].name,
                ese_sigs[ch->ca].name,
                k[l].cert_sz, k[l].pub_sz, l >= LVL_SERVER ? k[l].priv_sz : 0);
        }
        printf(" root %6d  int %6d  server %6d  client %6d\n",
               k[LVL_ROOT].cert_sz, k[LVL_INT].cert_sz, k[LVL_SERVER].cert_sz,
               k[LVL_CLIENT].cert_sz);
        for (l = 0; l < LVL_COUNT; l++) {
            key_free(&k[l]);
        }
    }

    fprintf(src, "const ese_chain_certs_t ese_chain_certs[] = {\n");
    for (c = 0; c < ese_chain_count; c++) {
        fprintf(src, "    { c%d_root, sizeof(c%d_root), c%d_int, sizeof(c%d_int),"
                     " c%d_server, sizeof(c%d_server), c%d_server_key,"
                     " sizeof(c%d_server_key), c%d_client, sizeof(c%d_client),"
                     " c%d_client_key, sizeof(c%d_client_key) },\n",
                c, c, c, c, c, c, c, c, c, c, c, c);
    }
    fprintf(src, "};\n");
    fclose(src);
    fclose(sizes);
    free(k);
    wc_FreeRng(&rng);
    wolfSSL_Cleanup();
    return 0;
}
