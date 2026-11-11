/* Drives the router's lwIP netif hooks (ACL, VPN kill switch, PMTU ICMP, MSS clamp,
 * TTL rewrite, pcap capture) with an attacker-controlled Ethernet frame. */
#include "netif_env.h"

#define RULE_LEN 22
static uint32_t rd32(const uint8_t *d) { uint32_t v; memcpy(&v, d, 4); return v; }
static uint16_t rd16(const uint8_t *d) { return (uint16_t)(d[0] | (d[1] << 8)); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12) return -1;
    uint8_t flags = data[0], sel = data[1];
    ap_mss_clamp = rd16(data + 2);
    ap_pmtu = rd16(data + 4);
    sta_ttl_override = data[6];
    my_ap_ip = rd32(data + 7) | 1;   /* never 0 */
    uint8_t nrules = data[11] & 3;
    data += 12; size -= 12;
    if (size < (size_t)nrules * RULE_LEN) return -1;

    vpn_enabled = flags & 1;
    vpn_killswitch = (flags >> 1) & 1;
    vpn_route_all = (flags >> 2) & 1;
    vpn_connected = (flags >> 3) & 1;
    client_stats_enabled = (flags >> 4) & 1;
    vpn_net = my_ap_ip & 0x00FFFFFF;
    vpn_mask = 0x00FFFFFF;
    mayhem_pcap_setup((flags >> 5) & 3 ? (((flags >> 5) & 3) == 1 ? 1 : 2) : 0, (flags >> 7) & 1);

    acl_init();
    /* hook 0..3 = ap input, ap output, sta input, sta output -> to_ap, from_ap, to_esp, from_esp */
    static const uint8_t hook_acl[4] = {ACL_TO_AP, ACL_FROM_AP, ACL_TO_ESP, ACL_FROM_ESP};
    uint8_t acl_no = hook_acl[(sel >> 3) & 3];
    for (int i = 0; i < nrules; i++) {
        const uint8_t *r = data + i * RULE_LEN;
        acl_add(acl_no, rd32(r), rd32(r + 4), rd32(r + 8), rd32(r + 12), r[16],
                rd16(r + 17), rd16(r + 19), r[21]);
    }
    data += nrules * RULE_LEN; size -= nrules * RULE_LEN;

    memset(client_stats, 0, sizeof(client_stats));
    if (size >= 12) {   /* one tracked client keyed by the frame's src or dst MAC */
        client_stats[0].active = 1;
        memcpy(client_stats[0].mac, (sel & 4) ? data + 6 : data, 6);
    }

    original_netif_input = original_ap_netif_input = orig_input;
    original_netif_linkoutput = original_ap_netif_linkoutput = orig_output;
    sta_netif = ap_netif = (struct netif *)calloc(1, sizeof(struct netif));

    size_t split = (sel & 0x20) && size > 1 ? 1 + (data[0] % (size - 1)) : size;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, split, PBUF_RAM);
    memcpy(p->payload, data, split);
    if (split < size) {
        struct pbuf *q = pbuf_alloc(PBUF_RAW, size - split, PBUF_RAM);
        memcpy(q->payload, data + split, size - split);
        p->next = q;
        p->tot_len = size;
    }
    g_input = p;
    g_input_freed = 0;

    switch ((sel >> 3) & 3) {
    case 0: ap_netif_input_hook(p, sta_netif); break;
    case 1: ap_netif_linkoutput_hook(sta_netif, p); break;
    case 2: netif_input_hook(p, sta_netif); break;
    default: netif_linkoutput_hook(sta_netif, p); break;
    }
    if (!g_input_freed) pbuf_free(p);

    free(sta_netif);
    sta_netif = ap_netif = NULL;
    mayhem_pcap_teardown();
    return 0;
}
