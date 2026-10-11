/* Certificates and leaf keys for every chain, indexed like ese_chains[]. */
#ifndef ESE_CERTS_H
#define ESE_CERTS_H

typedef struct {
    const unsigned char *root;       unsigned int root_len;
    const unsigned char *inter;      unsigned int inter_len;
    const unsigned char *server;     unsigned int server_len;
    const unsigned char *server_key; unsigned int server_key_len;
    const unsigned char *client;     unsigned int client_len;
    const unsigned char *client_key; unsigned int client_key_len;
} ese_chain_certs_t;

extern const ese_chain_certs_t ese_chain_certs[];

/* Stateful-signature verify vectors over ese_bench_msg(), from the chain CAs. */
extern const unsigned char ese_lms_h10_pub[];
extern const unsigned int ese_lms_h10_pub_len;
extern const unsigned char ese_lms_h10_sig[];
extern const unsigned int ese_lms_h10_sig_len;
extern const unsigned char ese_lms_h15_pub[];
extern const unsigned int ese_lms_h15_pub_len;
extern const unsigned char ese_lms_h15_sig[];
extern const unsigned int ese_lms_h15_sig_len;
extern const unsigned char ese_xmss_h10_pub[];
extern const unsigned int ese_xmss_h10_pub_len;
extern const unsigned char ese_xmss_h10_sig[];
extern const unsigned int ese_xmss_h10_sig_len;
extern const unsigned char ese_xmss_h16_pub[];
extern const unsigned int ese_xmss_h16_pub_len;
extern const unsigned char ese_xmss_h16_sig[];
extern const unsigned int ese_xmss_h16_sig_len;

/* Extra stateful-signature verify vectors from ese_hbsgen (ESE_ALL_PQC_PARAMS). */
typedef struct {
    const char *name;
    int lms_parm;           /* enum wc_LmsParm, 0 for XMSS */
    const char *xmss_parm;  /* NULL for LMS */
    const unsigned char *pub; unsigned int pub_len;
    const unsigned char *sig; unsigned int sig_len;
} ese_hbs_vec_t;

extern const ese_hbs_vec_t ese_hbs_vecs[];
extern const int ese_hbs_vec_count;

#endif /* ESE_CERTS_H */
