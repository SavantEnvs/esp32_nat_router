#ifndef MAYHEM_FREERTOS_H
#define MAYHEM_FREERTOS_H
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include "esp_attr.h"
typedef uint32_t TickType_t;
typedef int BaseType_t;
#define pdTRUE  1
#define pdFALSE 0
#define pdPASS  1
#define pdFAIL  0
#define portMAX_DELAY 0xFFFFFFFFu
#endif
