#ifndef MAYHEM_ESP_LOG_H
#define MAYHEM_ESP_LOG_H
#include <stdio.h>
#include "esp_err.h"
/* Logging is formatted (so format-string bugs still execute) but discarded. */
static inline int mayhem_log_sink(const char *fmt, ...);
static inline int mayhem_log_sink(const char *fmt, ...) { (void)fmt; return 0; }
#define MAYHEM_LOG(tag, fmt, ...) ((void)(tag), (void)(0 && mayhem_log_sink(fmt, ##__VA_ARGS__)))
#define ESP_LOGE(tag, fmt, ...) MAYHEM_LOG(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) MAYHEM_LOG(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) MAYHEM_LOG(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) MAYHEM_LOG(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) MAYHEM_LOG(tag, fmt, ##__VA_ARGS__)
#endif
