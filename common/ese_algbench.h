/* Raw per-operation benchmark: one sample per call, for median/p99. */
#ifndef ESE_ALGBENCH_H
#define ESE_ALGBENCH_H

#include <stdint.h>

typedef struct {
    const char *alg;
    const char *op;
    int n;           /* 0 = ESE_N_DEFAULT */
} ese_alg_op_t;

typedef struct {
    int32_t status;
    uint64_t ns;
    uint32_t heap_peak;
    uint32_t heap_total;
    uint32_t heap_allocs;
} ese_alg_sample_t;

typedef struct ese_alg_state ese_alg_state_t;

extern const ese_alg_op_t ese_alg_ops[];
extern const int ese_alg_op_count;

int ese_alg_find(const char *alg, const char *op);
int ese_alg_default_n(int idx);

/* Setup (keys, reference signatures) runs outside the measured region. */
int ese_alg_setup(int idx, ese_alg_state_t **st);
void ese_alg_run(ese_alg_state_t *st, int n, ese_alg_sample_t *out);
/* Heap the keys hold after the run, including their structs; 0 for keygen. */
uint32_t ese_alg_key_held(const ese_alg_state_t *st);
void ese_alg_teardown(ese_alg_state_t *st);

#endif /* ESE_ALGBENCH_H */
