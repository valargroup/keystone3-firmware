#ifndef _SIMULATOR_MEMORY_H
#define _SIMULATOR_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *SimulatorSramMalloc(size_t size, const char *file, int line, const char *func);
void SimulatorSramFree(void *p, const char *file, int line, const char *func);
void *SimulatorSramRealloc(void *p, size_t size, const char *file, int line, const char *func);

void *SimulatorExtMalloc(size_t size, const char *file, int line, const char *func);
void SimulatorExtFree(void *p, const char *file, int line, const char *func);
void *SimulatorExtRealloc(void *p, size_t size, const char *file, int line, const char *func);

void SimulatorSetRustAllocatorHostMode(bool enabled);
void SimulatorPrintHeapInfo(const char *context);

#endif
