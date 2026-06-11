#ifdef SIMULATOR_TRACK_MEMORY

#include "simulator_memory.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SIMULATOR_SRAM_REFERENCE_SIZE        ((size_t)1024 * 440)
#define SIMULATOR_PSRAM_REFERENCE_SIZE       ((size_t)0x00800000)
#define SIMULATOR_ALLOC_MAGIC                0x534D454DU
#define SIMULATOR_HOST_ALLOC_KIND            0xFFFFFFFFU

typedef struct {
    size_t requestedSize;
    size_t allocatedSize;
    uint32_t heapKind;
    uint32_t magic;
} SimulatorAllocationHeader_t;

typedef struct {
    const char *name;
    size_t totalBytes;
    size_t currentBytes;
    size_t peakBytes;
    size_t currentRequestedBytes;
    size_t peakRequestedBytes;
    size_t successfulAllocations;
    size_t successfulFrees;
    size_t failedAllocations;
} SimulatorHeap_t;

typedef enum {
    SIMULATOR_HEAP_SRAM = 0,
    SIMULATOR_HEAP_PSRAM = 1,
} SimulatorHeapKind_t;

static SimulatorHeap_t g_sramHeap = {
    .name = "SRAM",
    .totalBytes = SIMULATOR_SRAM_REFERENCE_SIZE,
};
static SimulatorHeap_t g_psramHeap = {
    .name = "PSRAM",
    .totalBytes = SIMULATOR_PSRAM_REFERENCE_SIZE,
};
static bool g_rustAllocatorHostMode = false;

static size_t AlignUp(size_t value)
{
    const size_t alignment = sizeof(max_align_t);
    return (value + alignment - 1) & ~(alignment - 1);
}

static SimulatorHeap_t *SimulatorGetHeap(uint32_t heapKind)
{
    switch (heapKind) {
    case SIMULATOR_HEAP_SRAM:
        return &g_sramHeap;
    case SIMULATOR_HEAP_PSRAM:
        return &g_psramHeap;
    default:
        return NULL;
    }
}

static void SimulatorHeapRecordAlloc(SimulatorHeap_t *heap, size_t requestedSize, size_t allocatedSize)
{
    heap->currentBytes += allocatedSize;
    heap->currentRequestedBytes += requestedSize;
    if (heap->currentBytes > heap->peakBytes) {
        heap->peakBytes = heap->currentBytes;
    }
    if (heap->currentRequestedBytes > heap->peakRequestedBytes) {
        heap->peakRequestedBytes = heap->currentRequestedBytes;
    }
    heap->successfulAllocations++;
}

static void SimulatorHeapRecordFree(SimulatorHeap_t *heap, size_t requestedSize, size_t allocatedSize)
{
    heap->currentBytes = heap->currentBytes >= allocatedSize ? heap->currentBytes - allocatedSize : 0;
    heap->currentRequestedBytes = heap->currentRequestedBytes >= requestedSize ? heap->currentRequestedBytes - requestedSize : 0;
    heap->successfulFrees++;
}

static void *SimulatorHostMallocWithHeader(size_t size, uint32_t heapKind)
{
    size_t requestedSize = size;
    size_t allocatedSize = AlignUp(size == 0 ? 1 : size);
    size_t totalSize = sizeof(SimulatorAllocationHeader_t) + allocatedSize;
    SimulatorAllocationHeader_t *header = (SimulatorAllocationHeader_t *)malloc(totalSize);
    if (header == NULL) {
        SimulatorHeap_t *heap = SimulatorGetHeap(heapKind);
        if (heap != NULL) {
            heap->failedAllocations++;
        }
        return NULL;
    }

    header->requestedSize = requestedSize;
    header->allocatedSize = allocatedSize;
    header->heapKind = heapKind;
    header->magic = SIMULATOR_ALLOC_MAGIC;

    SimulatorHeap_t *heap = SimulatorGetHeap(heapKind);
    if (heap != NULL) {
        SimulatorHeapRecordAlloc(heap, requestedSize, allocatedSize);
    }
    return (uint8_t *)header + sizeof(SimulatorAllocationHeader_t);
}

static void *SimulatorHeapMalloc(SimulatorHeapKind_t heapKind, size_t size, const char *file, int line, const char *func)
{
    void *p = SimulatorHostMallocWithHeader(size, (uint32_t)heapKind);
    if (p == NULL) {
        SimulatorHeap_t *heap = SimulatorGetHeap((uint32_t)heapKind);
        printf(
            "[sim-mem] %s host allocation failed: requested=%zu at %s:%d %s\n",
            heap != NULL ? heap->name : "UNKNOWN",
            size,
            file,
            line,
            func);
        SimulatorPrintHeapInfo("allocation failed");
    }
    return p;
}

static SimulatorAllocationHeader_t *SimulatorGetAllocationHeader(void *p)
{
    if (p == NULL) {
        return NULL;
    }

    SimulatorAllocationHeader_t *header =
        (SimulatorAllocationHeader_t *)((uint8_t *)p - sizeof(SimulatorAllocationHeader_t));
    if (header->magic != SIMULATOR_ALLOC_MAGIC) {
        return NULL;
    }
    return header;
}

static void SimulatorHeapFree(void *p, const char *file, int line, const char *func)
{
    if (p == NULL) {
        return;
    }

    SimulatorAllocationHeader_t *header = SimulatorGetAllocationHeader(p);
    if (header == NULL) {
        printf("[sim-mem] free ignored for untracked pointer %p at %s:%d %s\n", p, file, line, func);
        return;
    }

    SimulatorHeap_t *heap = SimulatorGetHeap(header->heapKind);
    if (heap != NULL) {
        SimulatorHeapRecordFree(heap, header->requestedSize, header->allocatedSize);
    }
    header->magic = 0;
    free(header);
}

static void *SimulatorHeapRealloc(
    SimulatorHeapKind_t heapKind,
    void *p,
    size_t newSize,
    const char *file,
    int line,
    const char *func)
{
    if (p == NULL) {
        return SimulatorHeapMalloc(heapKind, newSize, file, line, func);
    }
    if (newSize == 0) {
        SimulatorHeapFree(p, file, line, func);
        return NULL;
    }

    SimulatorAllocationHeader_t *header = SimulatorGetAllocationHeader(p);
    if (header == NULL) {
        printf("[sim-mem] realloc ignored for untracked pointer %p at %s:%d %s\n", p, file, line, func);
        return NULL;
    }

    size_t oldRequestedSize = header->requestedSize;
    size_t oldAllocatedSize = header->allocatedSize;
    size_t newAllocatedSize = AlignUp(newSize);
    size_t totalSize = sizeof(SimulatorAllocationHeader_t) + newAllocatedSize;
    SimulatorAllocationHeader_t *newHeader = (SimulatorAllocationHeader_t *)realloc(header, totalSize);
    if (newHeader == NULL) {
        SimulatorHeap_t *heap = SimulatorGetHeap(header->heapKind);
        if (heap != NULL) {
            heap->failedAllocations++;
        }
        printf(
            "[sim-mem] realloc failed: requested=%zu at %s:%d %s\n",
            newSize,
            file,
            line,
            func);
        SimulatorPrintHeapInfo("realloc failed");
        return NULL;
    }

    SimulatorHeap_t *oldHeap = SimulatorGetHeap(newHeader->heapKind);
    if (oldHeap != NULL) {
        SimulatorHeapRecordFree(oldHeap, oldRequestedSize, oldAllocatedSize);
    }

    newHeader->requestedSize = newSize;
    newHeader->allocatedSize = newAllocatedSize;
    newHeader->heapKind = heapKind;
    newHeader->magic = SIMULATOR_ALLOC_MAGIC;

    SimulatorHeap_t *newHeap = SimulatorGetHeap(newHeader->heapKind);
    if (newHeap != NULL) {
        SimulatorHeapRecordAlloc(newHeap, newSize, newAllocatedSize);
    }
    return (uint8_t *)newHeader + sizeof(SimulatorAllocationHeader_t);
}

void *SimulatorSramMalloc(size_t size, const char *file, int line, const char *func)
{
    return SimulatorHeapMalloc(SIMULATOR_HEAP_SRAM, size, file, line, func);
}

void SimulatorSramFree(void *p, const char *file, int line, const char *func)
{
    SimulatorHeapFree(p, file, line, func);
}

void *SimulatorSramRealloc(void *p, size_t size, const char *file, int line, const char *func)
{
    return SimulatorHeapRealloc(SIMULATOR_HEAP_SRAM, p, size, file, line, func);
}

void *SimulatorExtMalloc(size_t size, const char *file, int line, const char *func)
{
    return SimulatorHeapMalloc(SIMULATOR_HEAP_PSRAM, size, file, line, func);
}

void SimulatorExtFree(void *p, const char *file, int line, const char *func)
{
    SimulatorHeapFree(p, file, line, func);
}

void *SimulatorExtRealloc(void *p, size_t size, const char *file, int line, const char *func)
{
    return SimulatorHeapRealloc(SIMULATOR_HEAP_PSRAM, p, size, file, line, func);
}

void *SramMallocTrack(size_t size, const char *file, int line, const char *func)
{
    return SimulatorSramMalloc(size, file, line, func);
}

void SramFreeTrack(void *p, const char *file, int line, const char *func)
{
    SimulatorSramFree(p, file, line, func);
}

void *SramReallocTrack(void *p, size_t size, const char *file, int line, const char *func)
{
    return SimulatorSramRealloc(p, size, file, line, func);
}

void *SramMalloc(size_t size)
{
    return SimulatorSramMalloc(size, "simulator", 0, "SramMalloc");
}

void SramFree(void *p)
{
    SimulatorSramFree(p, "simulator", 0, "SramFree");
}

void *ExtMallocTrack(size_t size, const char *file, int line, const char *func)
{
    return SimulatorExtMalloc(size, file, line, func);
}

void ExtFreeTrack(void *p, const char *file, int line, const char *func)
{
    SimulatorExtFree(p, file, line, func);
}

void *ExtMalloc(size_t size)
{
    return SimulatorExtMalloc(size, "simulator", 0, "ExtMalloc");
}

void ExtFree(void *p)
{
    SimulatorExtFree(p, "simulator", 0, "ExtFree");
}

void *ExtRealloc(void *p, size_t newSize)
{
    return SimulatorExtRealloc(p, newSize, "simulator", 0, "ExtRealloc");
}

void *RustMalloc(int32_t size)
{
    if (size < 0) {
        return NULL;
    }
    if (g_rustAllocatorHostMode) {
        void *p = SimulatorHostMallocWithHeader((size_t)size, SIMULATOR_HOST_ALLOC_KIND);
        if (p == NULL) {
            printf("[sim-mem] Rust host allocation failed: requested=%d\n", size);
        }
        return p;
    }
    return SimulatorExtMalloc((size_t)size, "rust", 0, "RustMalloc");
}

void RustFree(void *p)
{
    SimulatorHeapFree(p, "rust", 0, "RustFree");
}

void SimulatorSetRustAllocatorHostMode(bool enabled)
{
    g_rustAllocatorHostMode = enabled;
}

static void SimulatorPrintOneHeap(const SimulatorHeap_t *heap)
{
    size_t freeBytes = heap->currentBytes < heap->totalBytes ? heap->totalBytes - heap->currentBytes : 0;
    size_t minFreeBytes = heap->peakBytes < heap->totalBytes ? heap->totalBytes - heap->peakBytes : 0;
    printf(
        "[sim-mem] %s total=%zu used=%zu free=%zu min_free=%zu peak_used=%zu requested=%zu peak_requested=%zu allocs=%zu frees=%zu failed=%zu\n",
        heap->name,
        heap->totalBytes,
        heap->currentBytes,
        freeBytes,
        minFreeBytes,
        heap->peakBytes,
        heap->currentRequestedBytes,
        heap->peakRequestedBytes,
        heap->successfulAllocations,
        heap->successfulFrees,
        heap->failedAllocations);
}

void SimulatorPrintHeapInfo(const char *context)
{
    printf("[sim-mem] %s\n", context != NULL ? context : "heap snapshot");
    SimulatorPrintOneHeap(&g_sramHeap);
    SimulatorPrintOneHeap(&g_psramHeap);
}

#else

void SimulatorMemoryDisabledTranslationUnit(void) {}

void SimulatorSetRustAllocatorHostMode(bool enabled)
{
    (void)enabled;
}

#endif
