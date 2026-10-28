#ifndef _PQ_BENCH_H
#define _PQ_BENCH_H

#include "stdint.h"
#include "stdbool.h"
#include "librust_c.h"

#ifdef FEATURE_PQ_BENCH

// Hash-based signature benchmark: times key generation, signing and verification of
// SLH-DSA-SHA2-192s and 192f (the Rust side is rust/apps/pq_bench).

#define PQ_BENCH_ALL_SCHEMES        (-1)
#define PQ_BENCH_MAX_SCHEMES        2
#define PQ_BENCH_DEFAULT_ITERATIONS 3

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

// What the last run did, kept in SPI flash so it survives a reset. The device writes it before
// every step, so after a crash it names the step that was running.
typedef struct {
    uint32_t magic;
    uint32_t running;           // 1 from the start of a run until it finishes
    uint32_t scheme;            // the step running now, valid while running
    uint32_t step;              // 0 keygen, 1 sign, 2 verify
    uint32_t iteration;         // counted from 0
    uint32_t iterations;
    uint32_t resultCount;       // schemes finished, in run order
    PqBenchResult_t results[PQ_BENCH_MAX_SCHEMES];
} PqBenchRecord_t;

// Starts a run of one scheme, or both with PQ_BENCH_ALL_SCHEMES. iterations == 0 uses
// PQ_BENCH_DEFAULT_ITERATIONS. On the device the run happens on its own task and results also
// go to the UART as CSV; the simulator runs it before returning. Returns false when a run is
// already in progress or the task cannot be created.
bool PqBenchStart(int32_t scheme, uint32_t iterations);

PqBenchState_t PqBenchGetState(void);

// Why the last PqBenchStart call returned false, for the screen; empty otherwise.
const char *PqBenchGetError(void);

// The last run, loaded from flash on first use. While a run is in progress it shows the step
// running now; when no run is in progress and record->running is set, the device reset during
// that step. Returns NULL when there has been no run.
const PqBenchRecord_t *PqBenchGetRecord(void);

// "keygen", "sign" or "verify".
const char *PqBenchStepName(uint32_t step);

#endif

#endif
