/* Crypto-callback device for hardware offload builds; software otherwise. */
#ifndef ESE_DEVID_H
#define ESE_DEVID_H

#ifdef WOLFSSL_ELS_PKC
    #define ESE_DEVID WOLFSSL_ELS_PKC_DEVID
#else
    #define ESE_DEVID INVALID_DEVID
#endif

#endif /* ESE_DEVID_H */
