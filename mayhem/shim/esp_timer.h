#ifndef MAYHEM_ESP_TIMER_H
#define MAYHEM_ESP_TIMER_H
#include <stdint.h>
/* Deterministic clock: every call advances 0.6 s, so rate-limited log paths are reachable. */
static inline int64_t esp_timer_get_time(void) { static int64_t t; t += 600000; return t; }
#endif
