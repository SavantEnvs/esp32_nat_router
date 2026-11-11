#ifndef MAYHEM_ESP_NETIF_H
#define MAYHEM_ESP_NETIF_H
#include <stdint.h>
#include "esp_err.h"
#include "lwip/ip4_addr.h"
#define IPSTR "%d.%d.%d.%d"
#define esp_ip4_addr_get_byte(ipaddr, idx) (((const uint8_t *)(&(ipaddr)->addr))[idx])
#define IP2STR(ipaddr) esp_ip4_addr_get_byte(ipaddr, 0), esp_ip4_addr_get_byte(ipaddr, 1), \
                       esp_ip4_addr_get_byte(ipaddr, 2), esp_ip4_addr_get_byte(ipaddr, 3)
typedef struct esp_netif_obj esp_netif_t;
static inline esp_netif_t *esp_netif_get_handle_from_ifkey(const char *k) { (void)k; return 0; }
#endif
