/* Links one algorithm's API into a wolfCrypt image so its flash cost can be
 * read from the ELF; the image is built, never run. */
#include <string.h>
#include <time.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>

/* Inputs the compiler cannot see through, so no call is folded away. */
unsigned char fp_in[8192];
unsigned char fp_sig[20000];
unsigned char fp_out[8192];
word32 fp_len = sizeof(fp_in);
volatile int fp_sink;

time_t ese_time(time_t *t)
{
    if (t != NULL) {
        *t = 0;
    }
    return 0;
}

#ifndef FP_RNG
static int sha3_all(void)
{
    wc_Sha3 s3;
    wc_Shake sh;
    int ret = 0;

    ret |= wc_InitSha3_224(&s3, NULL, INVALID_DEVID);
    ret |= wc_Sha3_224_Update(&s3, fp_in, fp_len);
    ret |= wc_Sha3_224_Final(&s3, fp_out);
    wc_Sha3_224_Free(&s3);
    ret |= wc_InitSha3_256(&s3, NULL, INVALID_DEVID);
    ret |= wc_Sha3_256_Update(&s3, fp_in, fp_len);
    ret |= wc_Sha3_256_Final(&s3, fp_out);
    wc_Sha3_256_Free(&s3);
    ret |= wc_InitSha3_384(&s3, NULL, INVALID_DEVID);
    ret |= wc_Sha3_384_Update(&s3, fp_in, fp_len);
    ret |= wc_Sha3_384_Final(&s3, fp_out);
    wc_Sha3_384_Free(&s3);
    ret |= wc_InitSha3_512(&s3, NULL, INVALID_DEVID);
    ret |= wc_Sha3_512_Update(&s3, fp_in, fp_len);
    ret |= wc_Sha3_512_Final(&s3, fp_out);
    ret |= wc_InitShake128(&sh, NULL, INVALID_DEVID);
    ret |= wc_Shake128_Update(&sh, fp_in, fp_len);
    ret |= wc_Shake128_Final(&sh, fp_out, fp_len);
    ret |= wc_Shake128_Absorb(&sh, fp_in, fp_len);
    ret |= wc_Shake128_SqueezeBlocks(&sh, fp_out, 1);
    wc_Sha3_512_Free(&s3);
    wc_Shake128_Free(&sh);
    ret |= wc_InitShake256(&sh, NULL, INVALID_DEVID);
    ret |= wc_Shake256_Update(&sh, fp_in, fp_len);
    ret |= wc_Shake256_Final(&sh, fp_out, fp_len);
    ret |= wc_Shake256_Absorb(&sh, fp_in, fp_len);
    ret |= wc_Shake256_SqueezeBlocks(&sh, fp_out, 1);
    wc_Shake256_Free(&sh);
    return ret;
}
#endif

static int item(WC_RNG *rng)
{
    word32 len = fp_len;
    int res = 0;
    int ret = 0;

    (void)rng;
    (void)len;
    (void)res;
#if defined(FP_ECDSA_P256_FULL) || defined(FP_ECDSA_P256_VERIFY)
    ecc_key k;
    ret |= wc_ecc_init(&k);
  #ifdef FP_ECDSA_P256_FULL
    ret |= wc_ecc_make_key_ex(rng, 32, &k, ECC_SECP256R1);
    ret |= wc_ecc_sign_hash(fp_in, 32, fp_sig, &len, rng, &k);
    ret |= wc_ecc_export_x963(&k, fp_out, &len);
  #else
    ret |= wc_ecc_import_x963_ex(fp_in, 65, &k, ECC_SECP256R1);
  #endif
    ret |= wc_ecc_verify_hash(fp_sig, len, fp_in, 32, &res, &k);
    wc_ecc_free(&k);
#elif defined(FP_RSA3072_FULL) || defined(FP_RSA3072_VERIFY)
    RsaKey k;
    word32 idx = 0;
    ret |= wc_InitRsaKey(&k, NULL);
  #ifdef FP_RSA3072_FULL
    ret |= wc_RsaPrivateKeyDecode(fp_in, &idx, &k, fp_len);
    ret |= wc_RsaSetRNG(&k, rng);
    ret |= wc_RsaPSS_Sign(fp_in, 32, fp_sig, sizeof(fp_sig), WC_HASH_TYPE_SHA256,
                          WC_MGF1SHA256, &k, rng);
  #else
    ret |= wc_RsaPublicKeyDecodeRaw(fp_in, 384, fp_in + 384, 3, &k);
  #endif
    ret |= wc_RsaPSS_VerifyCheck(fp_sig, 384, fp_out, sizeof(fp_out), fp_in, 32,
                                 WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &k);
    (void)idx;
    wc_FreeRsaKey(&k);
#elif defined(FP_X25519_FULL)
    curve25519_key a, b;
    ret |= wc_curve25519_init(&a);
    ret |= wc_curve25519_init(&b);
    ret |= wc_curve25519_make_key(rng, 32, &a);
    ret |= wc_curve25519_import_public_ex(fp_in, 32, &b, EC25519_LITTLE_ENDIAN);
    ret |= wc_curve25519_export_public_ex(&a, fp_out, &len,
                                          EC25519_LITTLE_ENDIAN);
    ret |= wc_curve25519_shared_secret_ex(&a, &b, fp_out, &len,
                                          EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&a);
    wc_curve25519_free(&b);
#elif defined(FP_MLKEM768_FULL)
    MlKemKey k;
    ret |= wc_MlKemKey_Init(&k, WC_ML_KEM_768, NULL, INVALID_DEVID);
    ret |= wc_MlKemKey_MakeKey(&k, rng);
    ret |= wc_MlKemKey_EncodePublicKey(&k, fp_out, WC_ML_KEM_768_PUBLIC_KEY_SIZE);
    ret |= wc_MlKemKey_DecodePublicKey(&k, fp_in, WC_ML_KEM_768_PUBLIC_KEY_SIZE);
    ret |= wc_MlKemKey_Encapsulate(&k, fp_sig, fp_out, rng);
    ret |= wc_MlKemKey_Decapsulate(&k, fp_out, fp_sig,
                                   WC_ML_KEM_768_CIPHER_TEXT_SIZE);
    wc_MlKemKey_Free(&k);
#elif defined(FP_MLDSA44_FULL) || defined(FP_MLDSA44_VERIFY)
    wc_MlDsaKey k;
    ret |= wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID);
    ret |= wc_MlDsaKey_SetParams(&k, WC_ML_DSA_44);
  #ifdef FP_MLDSA44_FULL
    ret |= wc_MlDsaKey_MakeKey(&k, rng);
    ret |= wc_MlDsaKey_SignCtx(&k, NULL, 0, fp_sig, &len, fp_in, 130, rng);
    ret |= wc_MlDsaKey_ExportPubRaw(&k, fp_out, &len);
  #else
    ret |= wc_MlDsaKey_ImportPubRaw(&k, fp_in, 1312);
  #endif
    ret |= wc_MlDsaKey_VerifyCtx(&k, fp_sig, len, NULL, 0, fp_in, 130, &res);
    wc_MlDsaKey_Free(&k);
#elif defined(FP_FALCON512_FULL) || defined(FP_FALCON512_VERIFY)
    falcon_key k;
    ret |= wc_falcon_init(&k);
    ret |= wc_falcon_set_level(&k, 1);
  #ifdef FP_FALCON512_FULL
    ret |= wc_falcon_make_key(&k, rng);
    ret |= wc_falcon_sign_msg(fp_in, 130, fp_sig, &len, &k, rng);
    ret |= wc_falcon_export_public(&k, fp_out, &len);
  #else
    ret |= wc_falcon_import_public(fp_in, 897, &k);
  #endif
    ret |= wc_falcon_verify_msg(fp_sig, len, fp_in, 130, &res, &k);
    wc_falcon_free(&k);
#elif defined(FP_SLHDSA_FULL) || defined(FP_SLHDSA_VERIFY)
    SlhDsaKey k;
    ret |= wc_SlhDsaKey_Init(&k, (enum SlhDsaParam)fp_in[0], NULL, INVALID_DEVID);
  #ifdef FP_SLHDSA_FULL
    ret |= wc_SlhDsaKey_MakeKey(&k, rng);
    ret |= wc_SlhDsaKey_Sign(&k, NULL, 0, fp_in, 130, fp_sig, &len, rng);
    ret |= wc_SlhDsaKey_ExportPublic(&k, fp_out, &len);
  #else
    ret |= wc_SlhDsaKey_ImportPublic(&k, fp_in, 32);
  #endif
    ret |= wc_SlhDsaKey_Verify(&k, NULL, 0, fp_in, 130, fp_sig, len);
    wc_SlhDsaKey_Free(&k);
#elif defined(FP_LMS_VERIFY)
    LmsKey k;
    ret |= wc_LmsKey_Init(&k, NULL, INVALID_DEVID);
    ret |= wc_LmsKey_SetLmsParm(&k, (enum wc_LmsParm)fp_in[0]);
    ret |= wc_LmsKey_ImportPubRaw(&k, fp_in, 60);
    ret |= wc_LmsKey_Verify(&k, fp_sig, len, fp_in, 130);
    wc_LmsKey_Free(&k);
#elif defined(FP_XMSS_VERIFY)
    XmssKey k;
    ret |= wc_XmssKey_Init(&k, NULL, INVALID_DEVID);
    ret |= wc_XmssKey_SetParamStr(&k, (const char *)fp_out);
    ret |= wc_XmssKey_ImportPubRaw(&k, fp_in, 68);
    ret |= wc_XmssKey_Verify(&k, fp_sig, len, fp_in, 130);
    wc_XmssKey_Free(&k);
#elif defined(FP_MLKEM768_KEYGEN) || defined(FP_MLKEM768_ENCAP) || \
      defined(FP_MLKEM768_DECAP)
    MlKemKey k;
    ret |= wc_MlKemKey_Init(&k, WC_ML_KEM_768, NULL, INVALID_DEVID);
  #if defined(FP_MLKEM768_KEYGEN)
    ret |= wc_MlKemKey_MakeKey(&k, rng);
    ret |= wc_MlKemKey_EncodePublicKey(&k, fp_out, WC_ML_KEM_768_PUBLIC_KEY_SIZE);
  #elif defined(FP_MLKEM768_ENCAP)
    ret |= wc_MlKemKey_DecodePublicKey(&k, fp_in, WC_ML_KEM_768_PUBLIC_KEY_SIZE);
    ret |= wc_MlKemKey_Encapsulate(&k, fp_sig, fp_out, rng);
  #else
    ret |= wc_MlKemKey_DecodePrivateKey(&k, fp_in, WC_ML_KEM_768_PRIVATE_KEY_SIZE);
    ret |= wc_MlKemKey_Decapsulate(&k, fp_out, fp_sig,
                                   WC_ML_KEM_768_CIPHER_TEXT_SIZE);
  #endif
    wc_MlKemKey_Free(&k);
#elif defined(FP_MLDSA44_KEYGEN) || defined(FP_MLDSA44_SIGN)
    wc_MlDsaKey k;
    ret |= wc_MlDsaKey_Init(&k, NULL, INVALID_DEVID);
    ret |= wc_MlDsaKey_SetParams(&k, WC_ML_DSA_44);
  #ifdef FP_MLDSA44_KEYGEN
    ret |= wc_MlDsaKey_MakeKey(&k, rng);
    ret |= wc_MlDsaKey_ExportPubRaw(&k, fp_out, &len);
  #else
    ret |= wc_MlDsaKey_ImportPrivRaw(&k, fp_in, 2560);
    ret |= wc_MlDsaKey_SignCtx(&k, NULL, 0, fp_sig, &len, fp_in, 130, rng);
  #endif
    wc_MlDsaKey_Free(&k);
#elif defined(FP_FALCON512_KEYGEN) || defined(FP_FALCON512_SIGN)
    falcon_key k;
    ret |= wc_falcon_init(&k);
    ret |= wc_falcon_set_level(&k, 1);
  #ifdef FP_FALCON512_KEYGEN
    ret |= wc_falcon_make_key(&k, rng);
    ret |= wc_falcon_export_public(&k, fp_out, &len);
  #else
    ret |= wc_falcon_import_private_only(fp_in, 1281, &k);
    ret |= wc_falcon_sign_msg(fp_in, 130, fp_sig, &len, &k, rng);
  #endif
    wc_falcon_free(&k);
#elif defined(FP_SLHDSA_KEYGEN) || defined(FP_SLHDSA_SIGN)
    SlhDsaKey k;
    ret |= wc_SlhDsaKey_Init(&k, (enum SlhDsaParam)fp_in[0], NULL, INVALID_DEVID);
  #ifdef FP_SLHDSA_KEYGEN
    ret |= wc_SlhDsaKey_MakeKey(&k, rng);
    ret |= wc_SlhDsaKey_ExportPublic(&k, fp_out, &len);
  #else
    ret |= wc_SlhDsaKey_ImportPrivate(&k, fp_in, 64);
    ret |= wc_SlhDsaKey_Sign(&k, NULL, 0, fp_in, 130, fp_sig, &len, rng);
  #endif
    wc_SlhDsaKey_Free(&k);
#endif
    return ret;
}

int main(void)
{
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    ret |= wc_RNG_GenerateBlock(&rng, fp_out, fp_len);
#ifndef FP_RNG
    ret |= sha3_all();
#endif
    ret |= item(&rng);
    wc_FreeRng(&rng);
    fp_sink = ret + fp_in[0] + fp_sig[fp_len % sizeof(fp_sig)];
    return 0;
}
