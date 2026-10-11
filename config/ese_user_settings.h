/* wolfSSL settings shared by every ese_2026 build: the DUTs and the host tools. */
#ifndef ESE_USER_SETTINGS_H
#define ESE_USER_SETTINGS_H

/* Platform */
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_WRITEV
#define WOLFSSL_EXPERIMENTAL_SETTINGS

#ifdef __ZEPHYR__
    #define NO_FILESYSTEM
    #define WOLFSSL_GENERAL_ALIGNMENT 4
    #define SIZEOF_LONG_LONG 8
#endif

#if defined(__SIZEOF_INT128__) && !defined(HAVE___UINT128_T)
    #define HAVE___UINT128_T 1
#endif

#ifdef CONFIG_ESE_FOOTPRINT
    #define WOLFCRYPT_ONLY
#endif

/* TLS: 1.3 only, full handshakes, no resumption */
#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_HKDF
#define NO_SESSION_CACHE
#define NO_PSK
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_IP_ALT_NAME

/* Symmetric */
#define HAVE_AESGCM
#define NO_AES_CBC
#define GCM_TABLE_4BIT
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DSA
#define NO_DH
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Classic public key */
#define HAVE_ECC
#define ECC_USER_CURVES
#define ECC_TIMING_RESISTANT
#define ECC_SHAMIR
#define HAVE_CURVE25519
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_2048
#define SP_INT_BITS 3072
#define WOLFSSL_SP_SMALL_STACK

/* Post-quantum */
#define WOLFSSL_HAVE_MLKEM
#ifndef ESE_ALL_PQC_PARAMS
    #define WOLFSSL_NO_ML_KEM_512
    #define WOLFSSL_NO_ML_KEM_1024
#endif
#define WOLFSSL_PQC_HYBRIDS

#define WOLFSSL_HAVE_MLDSA
#ifndef ESE_ALL_PQC_PARAMS
    #define WOLFSSL_NO_ML_DSA_65
    #define WOLFSSL_NO_ML_DSA_87
#endif

#define HAVE_FALCON
#ifdef CONFIG_ESE_FALCON_FPR_DOUBLE
    #define WOLFSSL_FALCON_FPR_DOUBLE
#endif

#define WOLFSSL_HAVE_SLHDSA
#define WOLFSSL_SLHDSA_SHA2
#define WOLFSSL_SLHDSA_PARAM_128S
#define WOLFSSL_SLHDSA_PARAM_128F
#define WOLFSSL_SLHDSA_PARAM_SHA2_128S
#define WOLFSSL_SLHDSA_PARAM_SHA2_128F
#ifndef ESE_ALL_PQC_PARAMS
    #define WOLFSSL_SLHDSA_PARAM_NO_192S
    #define WOLFSSL_SLHDSA_PARAM_NO_192F
    #define WOLFSSL_SLHDSA_PARAM_NO_256S
    #define WOLFSSL_SLHDSA_PARAM_NO_256F
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S
    #define WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F
#endif

#define WOLFSSL_HAVE_LMS
#define WOLFSSL_HAVE_XMSS
#ifdef ESE_ALL_PQC_PARAMS
    #define WOLFSSL_LMS_MAX_LEVELS 2
    #define WOLFSSL_LMS_MAX_HEIGHT 20
    #define WOLFSSL_LMS_SHA256_192
    #define WOLFSSL_XMSS_MAX_HEIGHT 40
#else
    #define WOLFSSL_LMS_MAX_LEVELS 1
    #define WOLFSSL_LMS_MAX_HEIGHT 15
    #define WOLFSSL_XMSS_MAX_HEIGHT 16
#endif
#define WOLFSSL_WC_XMSS_MAX_HASH_SIZE 256

/* NXP EdgeLock offload (frdm_rw612 ELS variant, wolfSSL els_pkc branch) */
#ifdef CONFIG_WOLFSSL_ELS_PKC
    #define WOLFSSL_ELS_PKC
    #define WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB_KEYSTORE
#endif

/* PQC profile: Zephyr images default to smallmem, the host and Pi DUTs to default */
#if defined(CONFIG_ESE_PQC_DEFAULT)
    #define ESE_PQC_DEFAULT
#elif defined(CONFIG_ESE_PQC_SMALLMEM_FAST)
    #define ESE_PQC_SMALLMEM_FAST
#elif defined(CONFIG_ESE_PQC_CACHE)
    #define ESE_PQC_CACHE
#elif defined(CONFIG_ESE_PQC_SMALL)
    #define ESE_PQC_SMALL
#elif defined(__ZEPHYR__)
    #define ESE_PQC_SMALLMEM
#endif

#if defined(ESE_PQC_SMALLMEM) || defined(ESE_PQC_SMALLMEM_FAST)
    #define WOLFSSL_MLKEM_DYNAMIC_KEYS
    /* ML-KEM small-mem cannot build with the aarch64 assembly. */
    #if !defined(__aarch64__) || defined(CONFIG_ARCH_POSIX) || defined(ESE_NO_ASM)
        #define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
        #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #endif
    #define WOLFSSL_MLDSA_DYNAMIC_KEYS
    #define WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
    #define WOLFSSL_FALCON_DYNAMIC_KEYS
    #define WOLFSSL_WC_SLHDSA_SMALL_MEM
    #ifdef ESE_PQC_SMALLMEM
        #define WOLFSSL_MLDSA_SIGN_SMALLEST_MEM
        #define WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM
        #define WOLFSSL_FALCON_SIGN_SMALLEST_MEM
    #else
        #define WOLFSSL_MLDSA_SIGN_SMALL_MEM_PRECALC
        #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
        #define WOLFSSL_FALCON_SIGN_SMALL_MEM
    #endif
#elif defined(ESE_PQC_CACHE)
    #define WOLFSSL_MLKEM_CACHE_A
    #define WC_MLDSA_CACHE_PRIV_VECTORS
    #define WC_MLDSA_CACHE_PUB_VECTORS
    #define WC_FALCON_CACHE_EXPANDED_KEY
#elif defined(ESE_PQC_SMALL)
    #define WOLFSSL_MLKEM_SMALL
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #define WOLFSSL_MLDSA_SMALL
    #define WOLFSSL_MLDSA_NO_LARGE_CODE
    #define WOLFSSL_WC_SLHDSA_SMALL
    #define WOLFSSL_WC_LMS_SMALL
    #define WOLFSSL_WC_XMSS_SMALL
#endif

#ifdef ESE_HOST_TOOLS
    /* Cert generation and stateful signing are host-only. */
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_EXT
    #define WOLFSSL_ALT_NAMES
    #define WOLFSSL_KEY_GEN
    #define WOLFSSL_CUSTOM_OID
    #define HAVE_OID_ENCODING
#else
    #define WOLFSSL_LMS_VERIFY_ONLY
    #define WOLFSSL_XMSS_VERIFY_ONLY

    /* The host sends the wall clock over the control channel; DUTs have no RTC. */
    #include <time.h>
    #define TIME_OVERRIDES
    #define HAVE_TIME_T_TYPE
    #define HAVE_TM_TYPE
    #define XTIME ese_time
    #define XGMTIME gmtime_r
#endif

/* Assembly: best available per CPU */
#if defined(CONFIG_ARCH_POSIX) || defined(ESE_NO_ASM)
    /* native_sim, or an explicit portable-C build */
#elif defined(__aarch64__)
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_NO_HASH_RAW
    #define WOLFSSL_SP_ARM64
    #define WOLFSSL_SP_ARM64_ASM
    #define WOLFSSL_AARCH64_BUILD
    #ifndef __ARM_FEATURE_CRYPTO
        #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #endif
    #ifndef __ARM_FEATURE_QRDMX
        #define WOLFSSL_AARCH64_NO_SQRDMLSH
    #endif
#elif defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_MAIN__)
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_THUMB2
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #ifdef WOLFSSL_ELS_PKC
        #define WOLFSSL_NO_HASH_RAW
    #endif
    #define WOLFSSL_SP_ARM_CORTEX_M
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
#elif defined(__x86_64__)
    #define WOLFSSL_SP_X86_64
    #define WOLFSSL_X86_64_BUILD
#endif

#if defined(CONFIG_ESE_HEAP_TRACE) && !defined(ESE_HEAP_TRACE)
    #define ESE_HEAP_TRACE
#endif
/* Trace builds take their handshake markers from wolfSSL's debug log. */
#if defined(ESE_DEBUG_WOLFSSL) || defined(ESE_HEAP_TRACE)
    #define DEBUG_WOLFSSL
#endif

#endif /* ESE_USER_SETTINGS_H */
