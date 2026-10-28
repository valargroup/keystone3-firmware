#ifndef _PQ_BENCH_H
#define _PQ_BENCH_H

#include "stdint.h"
#include "stdbool.h"
#include "librust_c.h"

#ifdef FEATURE_PQ_BENCH

// Hash-based signature benchmark: times key generation, signing and verification of
// WOTS+, FORS and SLH-DSA (the Rust side is rust/apps/pq_bench).

#define PQ_BENCH_ALL_SCHEMES        (-1)
#define PQ_BENCH_MAX_SCHEMES        12
// Result status for a scheme that needs more stack than the benchmark task has.
#define PQ_BENCH_SKIPPED_STACK      (-100)

typedef enum {
    PQ_BENCH_IDLE,
    PQ_BENCH_RUNNING,
    PQ_BENCH_DONE,
} PqBenchState_t;

typedef struct {
    uint32_t scheme;
    int32_t status;             // PQ_BENCH_OK or a negative PQ_BENCH_* code
    PqBenchReport report;
} PqBenchResult_t;

// Starts a run of one scheme, or all of them with PQ_BENCH_ALL_SCHEMES. iterations == 0 uses
// pq_bench_default_iterations (fewer for the slow SLH-DSA "s" sets). On the device the run happens on
// its own task and results also go to the UART as CSV; the simulator runs it before returning.
// Returns false when a run is already in progress or the task cannot be created.
bool PqBenchStart(int32_t scheme, uint32_t iterations);

PqBenchState_t PqBenchGetState(void);

// The scheme running now, or -1 between schemes and when idle.
int32_t PqBenchGetCurrentScheme(void);

// Results of the last run, in run order; returns how many are valid.
uint32_t PqBenchGetResults(const PqBenchResult_t **results);

#endif

#endif
