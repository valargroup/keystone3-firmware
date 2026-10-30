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
#include "drv_gd25qxx.h"
#include "screen_manager.h"
#include "flash_address.h"
#endif

// Signatures are signed into heap memory, so the deepest scheme uses about 22 KB of stack on
// the Mac (192-bit leanSphincs); the on-chip stack leaves room for deeper configurations. The PSRAM stack
// keeps the size the old on-stack signing needed, to compare against earlier runs. Each stack is
// allocated on its first run and kept for later ones.
#define PQ_BENCH_ON_CHIP_STACK_BYTES    (64 * 1024)
#define PQ_BENCH_PSRAM_STACK_BYTES      (240 * 1024)
// Below the watchdog and command tasks (Realtime7), above everything else.
#define PQ_BENCH_HIGH_PRIORITY_LEVEL    osPriorityRealtime
#define PQ_BENCH_RECORD_MAGIC           0x50514235  // "PQB5"

static volatile PqBenchState_t g_pqBenchState = PQ_BENCH_IDLE;
static int32_t g_pqBenchScheme;
static uint32_t g_pqBenchIterations;
static uint32_t g_pqBenchOptions;
static char g_pqBenchError[96];
static PqBenchRecord_t g_pqBenchRecord;
static bool g_pqBenchRecordLoaded;

#ifdef COMPILE_SIMULATOR

static uint64_t PqBenchNowNs(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void LoadRecord(void)
{
}

static void SaveRecord(void)
{
}

#else

// Time from the OS tick plus the SysTick countdown inside the current tick. The cycle counter
// does not run on the MH1903, but SysTick always does: it drives the 1 ms OS tick, and its
// countdown splits each tick into LOAD + 1 counts, which gives sub-microsecond resolution.
static uint64_t PqBenchNowNs(void)
{
    static uint64_t last;
    uint32_t tick, load, remaining;
    uint64_t now;

    // Read again if the tick moved on between the two reads, so the countdown belongs to the tick.
    do {
        tick = osKernelGetTickCount();
        load = SysTick->LOAD;
        remaining = SysTick->VAL;
    } while (tick != osKernelGetTickCount());
    now = (uint64_t)tick * 1000000ULL + (uint64_t)(load - remaining) * 1000000ULL / (load + 1);
    // The countdown restarts a moment before the tick interrupt counts the new tick; never step
    // back across that gap, or a step's time would go negative.
    if (now < last) {
        now = last;
    }
    last = now;
    return now;
}

static void LoadRecord(void)
{
    Gd25FlashReadBuffer(SPI_FLASH_ADDR_PQ_BENCH, (uint8_t *)&g_pqBenchRecord, sizeof(g_pqBenchRecord));
}

static void SaveRecord(void)
{
    Gd25FlashSectorErase(SPI_FLASH_ADDR_PQ_BENCH);
    Gd25FlashWriteBuffer(SPI_FLASH_ADDR_PQ_BENCH, (const uint8_t *)&g_pqBenchRecord, sizeof(g_pqBenchRecord));
}

#endif

// Refuse to run with a clock that stands still, which would report every step as 0.
static bool PqBenchClockRuns(void)
{
    uint64_t first = PqBenchNowNs();
    for (volatile uint32_t i = 0; i < 10000; i++) {
    }
    return PqBenchNowNs() > first;
}

_Static_assert(sizeof(PqBenchRecord_t) <= 0x1000, "the record must fit one flash sector");

static void EnsureRecordLoaded(void)
{
    if (g_pqBenchRecordLoaded) {
        return;
    }
    g_pqBenchRecordLoaded = true;
    LoadRecord();
    if (g_pqBenchRecord.magic != PQ_BENCH_RECORD_MAGIC ||
            g_pqBenchRecord.scheme >= pq_bench_scheme_count() || g_pqBenchRecord.step > 2) {
        memset(&g_pqBenchRecord, 0, sizeof(g_pqBenchRecord));
        return;
    }
    if (g_pqBenchRecord.running) {
        printf("pqbench,last_run_reset_during,%s,%s,%lu,%lu,%s\r\n", pq_bench_scheme_name(g_pqBenchRecord.scheme),
               PqBenchStepName(g_pqBenchRecord.step), (unsigned long)g_pqBenchRecord.iteration + 1,
               (unsigned long)g_pqBenchRecord.iterations, PqBenchOptionsText(g_pqBenchRecord.options));
    }
}

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

// Called before each step, outside the timed part. Saving the step first means a reset
// during it leaves the step in flash.
static void PqBenchProgress(uint32_t step, uint32_t iteration)
{
    g_pqBenchRecord.step = step;
    g_pqBenchRecord.iteration = iteration;
    SaveRecord();
    printf("pqbench,step,%s,%s,%lu,%lu\r\n", pq_bench_scheme_name(g_pqBenchRecord.scheme), PqBenchStepName(step),
           (unsigned long)iteration + 1, (unsigned long)g_pqBenchRecord.iterations);
}

static void PqBenchRun(void)
{
    uint32_t first = 0, last = pq_bench_scheme_count() - 1;

    if (g_pqBenchScheme != PQ_BENCH_ALL_SCHEMES) {
        first = last = (uint32_t)g_pqBenchScheme;
    }
    if (g_pqBenchRecord.magic != PQ_BENCH_RECORD_MAGIC) {
        memset(&g_pqBenchRecord, 0, sizeof(g_pqBenchRecord));
        g_pqBenchRecord.magic = PQ_BENCH_RECORD_MAGIC;
    }
    g_pqBenchRecord.iterations = g_pqBenchIterations;
    g_pqBenchRecord.options = g_pqBenchOptions;
    printf("pqbench,options,%s\r\n", PqBenchOptionsText(g_pqBenchOptions));
    printf("pqbench,scheme,n,keygen_median_us,keygen_min_us,keygen_max_us,"
           "sign_median_us,sign_min_us,sign_max_us,verify_median_us,verify_min_us,verify_max_us,"
           "signature_bytes,public_key_bytes\r\n");
    for (uint32_t scheme = first; scheme <= last; scheme++) {
        PqBenchResult_t result = {.scheme = scheme, .options = g_pqBenchOptions};

        g_pqBenchRecord.running = 1;
        g_pqBenchRecord.scheme = scheme;
        g_pqBenchRecord.finished &= ~(1UL << scheme);
        result.status = pq_bench_run(scheme, g_pqBenchIterations, PqBenchNowNs, PqBenchProgress, &result.report);
        g_pqBenchRecord.results[scheme] = result;
        g_pqBenchRecord.finished |= 1UL << scheme;
        g_pqBenchRecord.running = 0;
        SaveRecord();
        PrintResult(&result);
    }
#ifndef COMPILE_SIMULATOR
    printf("pqbench,memory,stack_bytes=%lu,stack_free_bytes=%lu,heap_min_free_bytes=%lu\r\n",
           (unsigned long)((g_pqBenchOptions & PQ_BENCH_STACK_ON_CHIP) ? PQ_BENCH_ON_CHIP_STACK_BYTES
                           : PQ_BENCH_PSRAM_STACK_BYTES),
           (unsigned long)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)),
           (unsigned long)xPortGetMinimumEverFreeHeapSize());
#endif
    printf("pqbench,done\r\n");
}

#ifndef COMPILE_SIMULATOR
// One task per stack placement, each created on its first run and kept for the life of the
// firmware, so its stack is never freed and reused.
//
// When the screen locks, the device sleeps with PSRAM switched off, and other tasks can still be
// scheduled while it does. So between runs a task waits for a start signal instead of waking
// to poll (a task with its stack in PSRAM would fault and reset the device), and during a run
// the screen does not lock.
typedef struct {
    const char *name;
    uint32_t stackBytes;
    bool onChip;
    osThreadId_t id;
    StaticTask_t control;
} PqBenchTask_t;

static PqBenchTask_t g_pqBenchTasks[2] = {
    {.name = "PqBenchOnChip", .stackBytes = PQ_BENCH_ON_CHIP_STACK_BYTES, .onChip = true},
    {.name = "PqBenchPsram", .stackBytes = PQ_BENCH_PSRAM_STACK_BYTES, .onChip = false},
};
#define PQ_BENCH_START_FLAG 1U

static void PqBenchTask(void *argument)
{
    (void)argument;
    while (1) {
        osThreadFlagsWait(PQ_BENCH_START_FLAG, osFlagsWaitAny, osWaitForever);
        SetPageLockScreen(false);
        PqBenchRun();
        SetPageLockScreen(true);
        g_pqBenchState = PQ_BENCH_DONE;
    }
}

static bool PqBenchCreateTask(PqBenchTask_t *task)
{
    if (task->id != NULL) {
        return true;
    }
    void *stack = task->onChip ? pvPortMalloc(task->stackBytes) : PsramMalloc(task->stackBytes);
    if (stack == NULL) {
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "No %lu KB of %s for the stack (%lu KB free).",
                 (unsigned long)(task->stackBytes / 1024), task->onChip ? "on-chip RAM" : "PSRAM",
                 (unsigned long)((task->onChip ? xPortGetFreeHeapSize() : PsramGetFreeHeapSize()) / 1024));
        return false;
    }
    const osThreadAttr_t attributes = {
        .name = task->name,
        .cb_mem = &task->control,
        .cb_size = sizeof(task->control),
        .stack_mem = stack,
        .stack_size = task->stackBytes,
        .priority = (osPriority_t)(osPriorityLow - 1),
    };
    task->id = osThreadNew(PqBenchTask, task, &attributes);
    if (task->id == NULL) {
        task->onChip ? vPortFree(stack) : PsramFree(stack);
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "Could not create the benchmark task.");
        return false;
    }
    return true;
}
#endif

bool PqBenchStart(int32_t scheme, uint32_t iterations, uint32_t options)
{
    EnsureRecordLoaded();
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
    if (!PqBenchClockRuns()) {
        snprintf(g_pqBenchError, sizeof(g_pqBenchError), "The timer is not running, so times would read 0.");
        printf("pqbench,error,%s\r\n", g_pqBenchError);
        return false;
    }
    g_pqBenchScheme = scheme;
    g_pqBenchIterations = iterations ? iterations : PQ_BENCH_DEFAULT_ITERATIONS;
    g_pqBenchOptions = options;
#ifdef COMPILE_SIMULATOR
    g_pqBenchState = PQ_BENCH_RUNNING;
    PqBenchRun();
    g_pqBenchState = PQ_BENCH_DONE;
#else
    PqBenchTask_t *task = &g_pqBenchTasks[(options & PQ_BENCH_STACK_ON_CHIP) ? 0 : 1];
    if (!PqBenchCreateTask(task)) {
        printf("pqbench,error,%s\r\n", g_pqBenchError);
        return false;
    }
    // Low priority runs below every other task but the idle task; high priority runs above the
    // UI, so the screen does not update until the run ends.
    osThreadSetPriority(task->id, (options & PQ_BENCH_HIGH_PRIORITY) ? PQ_BENCH_HIGH_PRIORITY_LEVEL
                        : (osPriority_t)(osPriorityLow - 1));
    g_pqBenchState = PQ_BENCH_RUNNING;
    osThreadFlagsSet(task->id, PQ_BENCH_START_FLAG);
#endif
    return true;
}

const char *PqBenchGetError(void)
{
    return g_pqBenchError;
}

PqBenchState_t PqBenchGetState(void)
{
    return g_pqBenchState;
}

const PqBenchRecord_t *PqBenchGetRecord(void)
{
    EnsureRecordLoaded();
    return g_pqBenchRecord.magic == PQ_BENCH_RECORD_MAGIC ? &g_pqBenchRecord : NULL;
}

bool PqBenchHeapInPsram(void)
{
#ifdef COMPILE_SIMULATOR
    return false;
#else
    if (g_pqBenchOptions & PQ_BENCH_HEAP_ON_CHIP) {
        return false;
    }
    osThreadId_t current = osThreadGetId();
    return current != NULL && (current == g_pqBenchTasks[0].id || current == g_pqBenchTasks[1].id);
#endif
}

const char *PqBenchOptionsText(uint32_t options)
{
    static char text[64];
    snprintf(text, sizeof(text), "%s stack, %s heap, %s priority",
             (options & PQ_BENCH_STACK_ON_CHIP) ? "on-chip" : "PSRAM",
             (options & PQ_BENCH_HEAP_ON_CHIP) ? "on-chip" : "PSRAM",
             (options & PQ_BENCH_HIGH_PRIORITY) ? "high" : "low");
    return text;
}

const char *PqBenchStepName(uint32_t step)
{
    switch (step) {
    case 0:
        return "keygen";
    case 1:
        return "sign";
    default:
        return "verify";
    }
}

#endif
