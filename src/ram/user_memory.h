#ifndef _USER_MEMORY_H
#define _USER_MEMORY_H

#include "stdint.h"
#include "stdbool.h"
#include "stddef.h"

void *SramMallocTrack(size_t size, const char *file, int line, const char *func);
void SramFreeTrack(void *p, const char *file, int line, const char *func);
void *SramReallocTrack(void *p, size_t size, const char *file, int line, const char *func);
void *SramMalloc(size_t size);
void SramFree(void *p);

void *ExtMallocTrack(size_t size, const char *file, int line, const char *func);
void ExtFreeTrack(void *p, const char *file, int line, const char *func);
void *ExtMalloc(size_t size);
void ExtFree(void *p);
void *ExtRealloc(void *p, size_t newSize);

void *RustMalloc(int32_t size);
void RustFree(void *p);

void PrintHeapInfo(void);

#ifdef COMPILE_SIMULATOR
#include <stdlib.h>
#ifndef snprintf_s
#define snprintf_s                          snprintf
#endif
#ifndef memset_s
#define memset_s(dest, destsz, ch, count)   (memset(dest, ch, count), 0)
#endif
#ifndef strcpy_s
#define strcpy_s(dest, destsz, src)         (strcpy(dest, src), 0)
#endif
#ifndef strcat_s
#define strcat_s(dest, destsz, src)         (strcat(dest, src), 0)
#endif
#ifndef strncpy_s
#define strncpy_s(dest, destsz, src, size)  (strncpy(dest, src, size), 0)
#endif
#define memcpy_s(dest, destsz, src, count)  memcpy(dest, src, count)
#define strnlen_s(sstr, smax)               strnlen(sstr, smax)
#define strncat_s(str, max, src, len)       strncat(str, src, len)
#ifndef strcasecmp_s
#define strcasecmp_s(s, slen, dest, result_p) strcasecmp(s, dest)
#endif

#ifdef SIMULATOR_TRACK_MEMORY
#include "simulator_memory.h"
#define SRAM_MALLOC(size)                   SimulatorSramMalloc(size, __FILE__, __LINE__, __func__)
#define SRAM_FREE(p)                        SimulatorSramFree(p, __FILE__, __LINE__, __func__)
#define SRAM_REALLOC(p, size)               SimulatorSramRealloc(p, size, __FILE__, __LINE__, __func__)
#else
#define SRAM_MALLOC(size)                   malloc(size)
#define SRAM_FREE(p)                        free(p)
#define SRAM_REALLOC(p, size)               realloc(p, size)
#endif
#else
#include "safe_str_lib.h"
#include "safe_mem_lib.h"
#define SRAM_MALLOC(size)           SramMallocTrack(size, __FILE__, __LINE__, __func__)
#define SRAM_FREE(p)                SramFreeTrack(p, __FILE__, __LINE__, __func__)
#define SRAM_REALLOC(p, size)       SramReallocTrack(p, size, __FILE__, __LINE__, __func__)
#endif

#ifdef COMPILE_SIMULATOR
#ifdef SIMULATOR_TRACK_MEMORY
#define EXT_MALLOC(size)            SimulatorExtMalloc(size, __FILE__, __LINE__, __func__)
#define EXT_FREE(p)                 SimulatorExtFree(p, __FILE__, __LINE__, __func__)
#else
#define EXT_MALLOC(size)            malloc(size)
#define EXT_FREE(p)                 free(p)
#endif
#else
#define EXT_MALLOC(size)            ExtMallocTrack(size, __FILE__, __LINE__, __func__)
#define EXT_FREE(p)                 ExtFreeTrack(p, __FILE__, __LINE__, __func__)
#endif

#endif
