#ifndef MAYHEM_TASK_H
#define MAYHEM_TASK_H
#include "FreeRTOS.h"
typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
static inline void vTaskDelay(TickType_t t) { (void)t; }
static inline void vTaskDelete(TaskHandle_t h) { (void)h; }
static inline BaseType_t xTaskCreate(TaskFunction_t f, const char *n, uint32_t s, void *a, unsigned prio, TaskHandle_t *h)
{
    (void)f; (void)n; (void)s; (void)a; (void)prio;
    static int dummy;
    if (h) *h = &dummy;
    return pdPASS;
}
#endif
