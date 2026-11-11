#ifndef MAYHEM_ESP_WIFI_H
#define MAYHEM_ESP_WIFI_H
#include <stdint.h>
#include "esp_err.h"
typedef struct { int num; } wifi_sta_list_t;
static inline esp_err_t esp_wifi_ap_get_sta_list(wifi_sta_list_t *l) { l->num = 0; return ESP_OK; }
#endif
