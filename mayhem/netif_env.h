/* Environment for compiling the unmodified main/netif_hooks.c on a host: includes it,
 * then supplies the firmware globals, a malloc-backed pbuf allocator (exact-size payloads
 * so ASan sees every overrun) and capture stubs for the original netif callbacks. */
#ifndef MAYHEM_NETIF_ENV_H
#define MAYHEM_NETIF_ENV_H
#include "../main/netif_hooks.c"
#include "lwip/err.h"
#include <stdlib.h>

void mayhem_pcap_setup(int mode, int connected);
void mayhem_pcap_teardown(void);

/* ---- firmware globals referenced by netif_hooks.c ---- */
uint64_t sta_bytes_sent, sta_bytes_received;
int led_gpio = 2;
uint8_t led_lowactive;
uint8_t led_toggle;
int led_strip_gpio = 3;
uint8_t sta_ttl_override;
uint16_t ap_mss_clamp;
uint16_t ap_pmtu;
uint32_t my_ap_ip;
bool ap_connect = true;
uint16_t connect_count;
int32_t vpn_enabled, vpn_killswitch, vpn_route_all;
bool vpn_connected;
uint32_t vpn_tunnel_ip;
static uint32_t vpn_net, vpn_mask;
esp_netif_t *wifiSTA, *wifiAP;

struct netif *esp_netif_get_netif_impl(esp_netif_t *n) { (void)n; return NULL; }
bool vpn_is_connected(void) { return vpn_connected; }
bool vpn_in_subnet(uint32_t ip) { return (ip & vpn_mask) == vpn_net; }
void led_strip_notify_traffic(void) {}

/* ---- pbuf allocator: exact-size payloads so ASan sees every overrun ---- */
static struct pbuf *g_input;
static int g_input_freed;

struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type)
{
    (void)layer; (void)type;
    struct pbuf *p = calloc(1, sizeof(*p));
    p->payload = malloc(length ? length : 1);
    p->len = p->tot_len = length;
    p->ref = 1;
    return p;
}

u8_t pbuf_free(struct pbuf *p)
{
    if (p == g_input) g_input_freed = 1;
    while (p) {
        struct pbuf *n = p->next;
        free(p->payload);
        free(p);
        p = n;
    }
    return 1;
}

static err_t orig_input(struct pbuf *p, struct netif *n) { (void)n; pbuf_free(p); return ERR_OK; }
uint8_t g_out[2048];
size_t g_out_len;
static err_t orig_output(struct netif *n, struct pbuf *p)
{
    (void)n;
    g_out_len = p->tot_len < sizeof(g_out) ? p->tot_len : sizeof(g_out);
    size_t off = 0;
    for (struct pbuf *q = p; q && off < g_out_len; q = q->next) {
        size_t c = q->len < g_out_len - off ? q->len : g_out_len - off;
        memcpy(g_out + off, q->payload, c);
        off += c;
    }
    return ERR_OK;
}

#endif
