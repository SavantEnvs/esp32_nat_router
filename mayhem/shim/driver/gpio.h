#ifndef MAYHEM_GPIO_H
#define MAYHEM_GPIO_H
#include "esp_err.h"
static inline esp_err_t gpio_set_level(int gpio, uint32_t level) { (void)gpio; (void)level; return ESP_OK; }
#endif
