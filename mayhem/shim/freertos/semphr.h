#ifndef MAYHEM_SEMPHR_H
#define MAYHEM_SEMPHR_H
#include <stdlib.h>
#include "FreeRTOS.h"

/* Single-threaded model: a binary semaphore holds 0 or 1 tokens, a mutex starts available. */
struct mayhem_sem { int tokens; };
typedef struct mayhem_sem *SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    SemaphoreHandle_t s = calloc(1, sizeof(*s));
    if (s) s->tokens = 1;
    return s;
}
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) { return calloc(1, sizeof(struct mayhem_sem)); }
static inline void vSemaphoreDelete(SemaphoreHandle_t s) { free(s); }
static inline BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t t)
{
    (void)t;
    if (s->tokens > 0) { s->tokens = 0; return pdTRUE; }
    return pdFALSE;
}
static inline BaseType_t xSemaphoreGive(SemaphoreHandle_t s) { s->tokens = 1; return pdTRUE; }
#endif
