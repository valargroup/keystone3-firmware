#ifndef _PQ_BENCH_H
#define _PQ_BENCH_H

#include "stdint.h"
#include "stdbool.h"
#include "librust_c.h"

#ifdef FEATURE_PQ_BENCH

// Hash-based signature benchmark: times key generation, signing and verification of 192-bit
// leanSphincs, plus SHA-256 and SHA-512 on their own (the Rust side is rust/apps/pq_bench).

#define PQ_BENCH_ALL_SCHEMES        (-1)
#define PQ_BENCH_MAX_SCHEMES        32
// One round per run: a Run press does one key generation, one signature and one verification.
#define PQ_BENCH_DEFAULT_ITERATIONS 1

// Run options, to find where time goes on the device. With neither set the stack is in PSRAM
// and the task runs below every other task. Rust allocations always go to PSRAM.
#define PQ_BENCH_STACK_ON_CHIP      (1u << 0)   // stack in on-chip SRAM
#define PQ_BENCH_HIGH_PRIORITY      (1u << 1)   // above the UI, USB and touch tasks
#define PQ_BENCH_DEFAULT_OPTIONS    PQ_BENCH_STACK_ON_CHIP

typedef enum {
    PQ_BENCH_IDLE,
    PQ_BENCH_RUNNING,
    PQ_BENCH_DONE,
} PqBenchState_t;

typedef struct {
    uint32_t scheme;
    int32_t status;             // PQ_BENCH_OK or a negative PQ_BENCH_* code
    uint32_t options;           // PQ_BENCH_STACK_ON_CHIP and PQ_BENCH_HIGH_PRIORITY bits of the run
    PqBenchReport report;
} PqBenchResult_t;

// The latest result of every scheme, and the step running now, kept in SPI flash so it
// survives a reset. The device writes it before every step, so after a crash it names the
// step that was running.
typedef struct {
    uint32_t magic;
    uint32_t running;           // 1 from the start of a scheme's run until it finishes
    uint32_t scheme;            // the scheme running, or last run
    uint32_t step;              // 0 keygen, 1 sign, 2 verify
    uint32_t iteration;         // counted from 0
    uint32_t iterations;
    uint32_t options;           // of the run in progress, or last run
    uint32_t finished;          // bit i set: results[i] holds scheme i's latest run
    PqBenchResult_t results[PQ_BENCH_MAX_SCHEMES];  // indexed by scheme
} PqBenchRecord_t;

// Starts a run of one scheme, or all of them in turn with PQ_BENCH_ALL_SCHEMES. iterations == 0 uses
// PQ_BENCH_DEFAULT_ITERATIONS; options is a set of PQ_BENCH_STACK_ON_CHIP and PQ_BENCH_HIGH_PRIORITY. On the device the run happens on its own task and results also
// go to the UART as CSV; the simulator runs it before returning. Returns false when a run is
// already in progress or the task cannot be created.
bool PqBenchStart(int32_t scheme, uint32_t iterations, uint32_t options);

PqBenchState_t PqBenchGetState(void);

// Why the last PqBenchStart call returned false, for the screen; empty otherwise.
const char *PqBenchGetError(void);

// The record, loaded from flash on first use. While a run is in progress it shows the step
// running now; when no run is in progress and record->running is set, the device reset during
// that step. Returns NULL when nothing has run yet.
const PqBenchRecord_t *PqBenchGetRecord(void);

// True on the benchmark's task, whose Rust allocations go to PSRAM: leanSphincs needs about
// 230 KB of heap, more than the SRAM heap has free.
bool PqBenchIsCurrentTask(void);

// "on-chip stack, low priority" and the like, for the screen and the UART log.
const char *PqBenchOptionsText(uint32_t options);

// "keygen", "sign" or "verify".
const char *PqBenchStepName(uint32_t step);

#endif

#endif
