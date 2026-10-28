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
#endif

// slh-dsa builds each signature on the stack and copies it several times on the way out, so
// the large SLH-DSA sets need up to about 200 KB (pq_bench_stack_bytes). The task takes the
// largest of these that leaves PQ_BENCH_HEAP_RESERVE_BYTES of the heap free, and skips the
// schemes that would not fit. FreeRTOS counts the stack in 16-bit words of 4 bytes, so it
// cannot exceed 256 KB - 4.
static const uint32_t g_pqBenchStackChoices[] = {240 * 1024, 192 * 1024, 128 * 1024};
#define PQ_BENCH_HEAP_RESERVE_BYTES (64 * 1024)
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
static void PqBenchTask(void *argument)
{
    (void)argument;
    PqBenchRun();
    g_pqBenchState = PQ_BENCH_DONE;
    osThreadExit();
}
#endif

bool PqBenchStart(int32_t scheme, uint32_t iterations)
{
    if (g_pqBenchState == PQ_BENCH_RUNNING) {
        printf("pqbench,busy\r\n");
        return false;
    }
    if (scheme != PQ_BENCH_ALL_SCHEMES && (scheme < 0 || (uint32_t)scheme >= pq_bench_scheme_count())) {
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
    size_t freeHeap = xPortGetFreeHeapSize();
    g_pqBenchStackBytes = 0;
    for (size_t i = 0; i < sizeof(g_pqBenchStackChoices) / sizeof(g_pqBenchStackChoices[0]); i++) {
        if (freeHeap >= g_pqBenchStackChoices[i] + PQ_BENCH_HEAP_RESERVE_BYTES) {
            g_pqBenchStackBytes = g_pqBenchStackChoices[i];
            break;
        }
    }
    printf("pqbench,stack_bytes=%lu,free_heap_bytes=%lu\r\n", (unsigned long)g_pqBenchStackBytes,
           (unsigned long)freeHeap);
    const osThreadAttr_t attributes = {
        .name = "PqBenchTask",
        .stack_size = g_pqBenchStackBytes,
        .priority = (osPriority_t)osPriorityBelowNormal,
    };
    g_pqBenchState = PQ_BENCH_RUNNING;
    if (g_pqBenchStackBytes == 0 || osThreadNew(PqBenchTask, NULL, &attributes) == NULL) {
        printf("pqbench,error,cannot create the task; free heap %lu\r\n", (unsigned long)freeHeap);
        g_pqBenchState = PQ_BENCH_IDLE;
        return false;
    }
#endif
    return true;
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
