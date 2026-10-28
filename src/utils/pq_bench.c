#include "pq_bench.h"

#ifdef FEATURE_PQ_BENCH

#include "stdio.h"
#include "string.h"

#ifdef COMPILE_SIMULATOR
#include <time.h>
#else
#include "cmsis_os.h"
#include "FreeRTOS.h"
#include "task.h"
#include "mhscpu.h"
#include "psram_heap_4.h"
#endif

// slh-dsa builds each signature on the stack and copies it several times on the way out, so
// the large SLH-DSA sets need up to about 200 KB (pq_bench_stack_bytes). The SRAM heap has
// less than that free, so the stack lives in PSRAM, allocated on the first run and kept for
// later ones. FreeRTOS counts the stack in 16-bit words of 4 bytes, so it cannot exceed
// 256 KB - 4.
#define PQ_BENCH_STACK_BYTES        (240 * 1024)
// The C frames below the Rust call.
#define PQ_BENCH_STACK_MARGIN_BYTES (4 * 1024)
// Above this the cycle counter (32 bits at 204 MHz, about 21 s) may have wrapped, so elapsed
// time comes from the 1 ms tick instead.
#define PQ_BENCH_CYCLE_LIMIT_MS     10000

static volatile PqBenchState_t g_pqBenchState = PQ_BENCH_IDLE;
static PqBenchResult_t g_pqBenchResults[PQ_BENCH_MAX_SCHEMES];
static uint32_t g_pqBenchResultCount = 0;
static int32_t g_pqBenchScheme;
static uint32_t g_pqBenchIterations;
static uint32_t g_pqBenchStackBytes;
static volatile int32_t g_pqBenchCurrent = -1;
static char g_pqBenchError[96];

#ifdef COMPILE_SIMULATOR

static uint64_t PqBenchNowNs(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

#else

static uint64_t PqBenchNowNs(void)
{
    static bool started = false;
    static uint32_t lastCycles, lastTick;
    static uint64_t nowNs;
    uint32_t cycles, tick, elapsedTicks;

    if (!started) {
        CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
        DWT->CYCCNT = 0;
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
        started = true;
        lastCycles = DWT->CYCCNT;
        lastTick = osKernelGetTickCount();
        return nowNs;
    }
    cycles = DWT->CYCCNT;
    tick = osKernelGetTickCount();
    elapsedTicks = tick - lastTick;
    if (elapsedTicks < PQ_BENCH_CYCLE_LIMIT_MS) {
        nowNs += (uint64_t)(cycles - lastCycles) * 1000000000ULL / configCPU_CLOCK_HZ;
    } else {
        nowNs += (uint64_t)elapsedTicks * 1000000ULL;
    }
    lastCycles = cycles;
    lastTick = tick;
    return nowNs;
}

#endif

static unsigned long ToMicros(uint64_t ns)
{
    return (unsigned long)(ns / 1000);
}

static void PrintResult(const PqBenchResult_t *result)
{
    const PqBenchReport *r = &result->report;
    const char *name = pq_bench_scheme_name(result->scheme);

    if (result->status != PQ_BENCH_OK) {
        printf("pqbench,%s,error,%d\r\n", name, (int)result->status);
        return;
    }
    printf("pqbench,%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n", name,
           (unsigned long)r->iterations,
           ToMicros(r->keygen.median_ns), ToMicros(r->keygen.min_ns), ToMicros(r->keygen.max_ns),
           ToMicros(r->sign.median_ns), ToMicros(r->sign.min_ns), ToMicros(r->sign.max_ns),
           ToMicros(r->verify.median_ns), ToMicros(r->verify.min_ns), ToMicros(r->verify.max_ns),
           (unsigned long)r->signature_bytes, (unsigned long)r->public_key_bytes);
}

static void PqBenchRun(void)
{
    uint32_t count = pq_bench_scheme_count();
    uint32_t first = 0, last = count - 1;

    if (g_pqBenchScheme != PQ_BENCH_ALL_SCHEMES) {
        first = last = (uint32_t)g_pqBenchScheme;
    }
    g_pqBenchResultCount = 0;
    printf("pqbench,scheme,n,keygen_median_us,keygen_min_us,keygen_max_us,"
           "sign_median_us,sign_min_us,sign_max_us,verify_median_us,verify_min_us,verify_max_us,"
           "signature_bytes,public_key_bytes\r\n");
    for (uint32_t scheme = first; scheme <= last && g_pqBenchResultCount < PQ_BENCH_MAX_SCHEMES; scheme++) {
        PqBenchResult_t *result = &g_pqBenchResults[g_pqBenchResultCount];
        uint32_t iterations = g_pqBenchIterations ? g_pqBenchIterations : pq_bench_default_iterations(scheme);

        memset(result, 0, sizeof(*result));
        result->scheme = scheme;
        if (pq_bench_stack_bytes(scheme) + PQ_BENCH_STACK_MARGIN_BYTES > g_pqBenchStackBytes) {
            result->status = PQ_BENCH_SKIPPED_STACK;
            g_pqBenchResultCount++;
            printf("pqbench,%s,skipped,needs %lu KB of stack; the task has %lu KB\r\n",
                   pq_bench_scheme_name(scheme), (unsigned long)(pq_bench_stack_bytes(scheme) / 1024),
                   (unsigned long)(g_pqBenchStackBytes / 1024));
            continue;
        }
        // Printed before the run, so a crash shows which scheme caused it.
        printf("pqbench,start,%s\r\n", pq_bench_scheme_name(scheme));
        g_pqBenchCurrent = (int32_t)scheme;
        result->status = pq_bench_run(scheme, iterations, PqBenchNowNs, &result->report);
        g_pqBenchResultCount++;
        PrintResult(result);
    }
#ifndef COMPILE_SIMULATOR
    printf("pqbench,memory,stack_free_bytes=%lu,heap_min_free_bytes=%lu\r\n",
           (unsigned long)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());
#endif
    g_pqBenchCurrent = -1;
    printf("pqbench,done\r\n");
}

#ifndef COMPILE_SIMULATOR
static volatile bool g_pqBenchRequested;
static osThreadId_t g_pqBenchTask;
static StaticTask_t g_pqBenchTaskControl;

// Waits for runs for the life of the firmware, so its PSRAM stack is never freed and reused.
static void PqBenchTask(void *argument)
{
    (void)argument;
    while (1) {
        if (g_pqBenchRequested) {
            g_pqBenchRequested = false;
            PqBenchRun();
            g_pqBenchState = PQ_BENCH_DONE;
        }
        osDelay(100);
    }
}

static bool PqBenchCreateTask(void)
{
    if (g_pqBenchTask != NULL) {
        return true;
    }
    void *stack = PsramMalloc(PQ_BENCH_STACK_BYTES);
    if (stack == NULL) {
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "No %d KB of PSRAM for the stack (%lu KB free).",
                 PQ_BENCH_STACK_BYTES / 1024, (unsigned long)(PsramGetFreeHeapSize() / 1024));
        return false;
    }
    const osThreadAttr_t attributes = {
        .name = "PqBenchTask",
        .cb_mem = &g_pqBenchTaskControl,
        .cb_size = sizeof(g_pqBenchTaskControl),
        .stack_mem = stack,
        .stack_size = PQ_BENCH_STACK_BYTES,
        .priority = (osPriority_t)osPriorityBelowNormal,
    };
    g_pqBenchTask = osThreadNew(PqBenchTask, NULL, &attributes);
    if (g_pqBenchTask == NULL) {
        PsramFree(stack);
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "Could not create the benchmark task.");
        return false;
    }
    return true;
}
#endif

bool PqBenchStart(int32_t scheme, uint32_t iterations)
{
    g_pqBenchError[0] = '\0';
    if (g_pqBenchState == PQ_BENCH_RUNNING) {
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "A run is already in progress.");
        printf("pqbench,busy\r\n");
        return false;
    }
    if (scheme != PQ_BENCH_ALL_SCHEMES && (scheme < 0 || (uint32_t)scheme >= pq_bench_scheme_count())) {
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "Unknown scheme %d.", (int)scheme);
        printf("pqbench,error,unknown scheme %d\r\n", (int)scheme);
        return false;
    }
    g_pqBenchScheme = scheme;
    g_pqBenchIterations = iterations;
#ifdef COMPILE_SIMULATOR
    g_pqBenchStackBytes = UINT32_MAX;
    g_pqBenchState = PQ_BENCH_RUNNING;
    PqBenchRun();
    g_pqBenchState = PQ_BENCH_DONE;
#else
    if (!PqBenchCreateTask()) {
        printf("pqbench,error,%s\r\n", g_pqBenchError);
        return false;
    }
    g_pqBenchStackBytes = PQ_BENCH_STACK_BYTES;
    printf("pqbench,stack_bytes=%lu,in=psram\r\n", (unsigned long)g_pqBenchStackBytes);
    g_pqBenchState = PQ_BENCH_RUNNING;
    g_pqBenchRequested = true;
#endif
    return true;
}

const char *PqBenchGetError(void)
{
    return g_pqBenchError;
}

int32_t PqBenchGetCurrentScheme(void)
{
    return g_pqBenchCurrent;
}

PqBenchState_t PqBenchGetState(void)
{
    return g_pqBenchState;
}

uint32_t PqBenchGetResults(const PqBenchResult_t **results)
{
    *results = g_pqBenchResults;
    return g_pqBenchState == PQ_BENCH_DONE ? g_pqBenchResultCount : 0;
}

#endif
