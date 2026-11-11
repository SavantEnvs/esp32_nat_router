/* Known-answer tests for the router's packet path. Built with the project's normal flags
 * (no sanitizers); every result is printed so mayhem/test.sh can diff it against kat.expected. */
#include "netif_env.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "pcap_ringbuf.h"

static uint16_t csum(const uint8_t *d, size_t n, uint32_t sum)
{
    for (; n > 1; d += 2, n -= 2) sum += (uint32_t)(d[0] << 8 | d[1]);
    if (n) sum += (uint32_t)d[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Ethernet + IPv4 + TCP SYN carrying an MSS option (and a NOP/NOP pad), valid checksums. */
static size_t build_syn(uint8_t *f, uint16_t mss, uint16_t dport, int df)
{
    memset(f, 0, 80);
    memcpy(f, "\x02\x00\x00\x00\x00\x01", 6);
    memcpy(f + 6, "\x02\x00\x00\x00\x00\x02", 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    ip[0] = 0x45; ip[3] = 24 + 20; ip[6] = df ? 0x40 : 0; ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, "\xc0\xa8\x04\x02", 4);
    memcpy(ip + 16, "\x08\x08\x08\x08", 4);
    ip[10] = ip[11] = 0;
    uint16_t c = csum(ip, 20, 0); ip[10] = c >> 8; ip[11] = c & 0xFF;
    uint8_t *tcp = ip + 20;
    tcp[0] = 0x30; tcp[1] = 0x39; tcp[2] = dport >> 8; tcp[3] = dport & 0xFF;
    tcp[12] = 6 << 4; tcp[13] = 0x02; tcp[14] = 0xFF; tcp[15] = 0xFF;
    tcp[20] = 2; tcp[21] = 4; tcp[22] = mss >> 8; tcp[23] = mss & 0xFF;
    uint8_t pseudo[12];
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = 6; pseudo[10] = 0; pseudo[11] = 24;
    uint32_t s0 = 0;
    for (int i = 0; i < 12; i += 2) s0 += pseudo[i] << 8 | pseudo[i + 1];
    c = csum(tcp, 24, s0); tcp[16] = c >> 8; tcp[17] = c & 0xFF;
    return 14 + 20 + 24;
}

static int tcp_csum_ok(const uint8_t *f)
{
    const uint8_t *ip = f + 14, *tcp = ip + 20;
    uint8_t pseudo[12];
    memcpy(pseudo, ip + 12, 8); pseudo[8] = 0; pseudo[9] = 6; pseudo[10] = 0; pseudo[11] = 24;
    uint32_t s0 = 0;
    for (int i = 0; i < 12; i += 2) s0 += pseudo[i] << 8 | pseudo[i + 1];
    return csum(tcp, 24, s0) == 0;
}

static struct pbuf *mkpbuf(const uint8_t *f, size_t n)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, n, PBUF_RAM);
    memcpy(p->payload, f, n);
    return p;
}

static void setup(void)
{
    acl_init();
    mayhem_pcap_setup(0, 0);
    original_netif_input = original_ap_netif_input = orig_input;
    original_netif_linkoutput = original_ap_netif_linkoutput = orig_output;
    ap_mss_clamp = 0; ap_pmtu = 0; sta_ttl_override = 0; vpn_enabled = 0; vpn_killswitch = 0;
    vpn_connected = 0; vpn_route_all = 0; client_stats_enabled = 0;
    my_ap_ip = htonl(0xC0A80401);
    g_out_len = 0;
    g_input = NULL;
}

int main(void)
{
    uint8_t f[128];
    uint32_t ip, mask;
    struct netif nif;
    memset(&nif, 0, sizeof(nif));
    sta_netif = &nif;

    /* acl text parsers */
    int ok = acl_parse_ip("192.168.1.0/24", &ip, &mask);
    printf("parse_ip 192.168.1.0/24 ok=%d ip=%08x mask=%08x\n", ok, ntohl(ip), ntohl(mask));
    ok = acl_parse_ip("any", &ip, &mask);
    printf("parse_ip any ok=%d ip=%08x mask=%08x\n", ok, ntohl(ip), ntohl(mask));
    ok = acl_parse_ip("10.1.2.3", &ip, &mask);
    printf("parse_ip 10.1.2.3 ok=%d ip=%08x mask=%08x\n", ok, ntohl(ip), ntohl(mask));
    ok = acl_parse_ip("300.1.1.1/8", &ip, &mask);
    printf("parse_ip 300.1.1.1/8 ok=%d\n", ok);
    printf("parse_name from_ap=%d TO_ESP=%d bogus=%d\n", acl_parse_name("from_ap"), acl_parse_name("TO_ESP"), acl_parse_name("bogus"));
    char buf[32];
    acl_parse_ip("172.16.0.0/12", &ip, &mask);
    printf("format %s\n", acl_format_ip(ip, mask, buf, sizeof(buf)));

    /* acl packet matching: deny TCP to 8.8.8.0/24:80 on to_ap, with monitor flag */
    setup();
    uint32_t a, am, b, bm;
    acl_parse_ip("192.168.4.0/24", &a, &am);
    acl_parse_ip("8.8.8.0/24", &b, &bm);
    acl_add(ACL_TO_AP, a, am, b, bm, ACL_PROTO_TCP, 0, 80, ACL_DENY | ACL_MONITOR);
    size_t n = build_syn(f, 1460, 80, 0);
    printf("acl port80 result=%02x\n", acl_check_packet(ACL_TO_AP, mkpbuf(f, n)));
    n = build_syn(f, 1460, 81, 0);
    printf("acl port81 result=%02x\n", acl_check_packet(ACL_TO_AP, mkpbuf(f, n)));
    printf("acl hit_count=%u denied=%u\n", acl_get_rules(ACL_TO_AP)[0].hit_count, acl_get_stats(ACL_TO_AP)->packets_denied);

    /* denied packet is dropped (freed) by the hook, an allowed one reaches the original input */
    n = build_syn(f, 1460, 80, 0);
    struct pbuf *p = mkpbuf(f, n); g_input = p; g_input_freed = 0;
    err_t e = ap_netif_input_hook(p, &nif);
    printf("hook deny err=%d freed=%d\n", e, g_input_freed);

    /* MSS clamp with RFC 1624 incremental checksum */
    setup();
    ap_mss_clamp = 1400;
    n = build_syn(f, 1460, 443, 0);
    p = mkpbuf(f, n);
    ap_netif_linkoutput_hook(&nif, p);
    uint8_t *tcp = (uint8_t *)p->payload + 14 + 20;
    printf("mss clamp 1460->%u csum_valid=%d\n", tcp[22] << 8 | tcp[23], tcp_csum_ok(p->payload));
    pbuf_free(p);
    n = build_syn(f, 1200, 443, 0);
    p = mkpbuf(f, n);
    ap_netif_linkoutput_hook(&nif, p);
    tcp = (uint8_t *)p->payload + 14 + 20;
    printf("mss keep 1200->%u csum_valid=%d\n", tcp[22] << 8 | tcp[23], tcp_csum_ok(p->payload));
    pbuf_free(p);

    /* TTL override with incremental IP header checksum */
    setup();
    sta_ttl_override = 65;
    n = build_syn(f, 1460, 443, 0);
    p = mkpbuf(f, n);
    netif_linkoutput_hook(&nif, p);
    const uint8_t *iph = (uint8_t *)p->payload + 14;
    printf("ttl override ttl=%u ip_csum_valid=%d sta_bytes_sent=%llu\n", iph[8], csum(iph, 20, 0) == 0,
           (unsigned long long)sta_bytes_sent);
    pbuf_free(p);

    /* PMTU: DF packet larger than the path MTU provokes ICMP fragmentation needed */
    setup();
    ap_pmtu = 40;
    n = build_syn(f, 1460, 443, 1);
    p = mkpbuf(f, n); g_input = p; g_input_freed = 0;
    ap_netif_input_hook(p, &nif);
    const uint8_t *icmp = g_out + 14 + 20;
    printf("pmtu icmp len=%zu type=%u code=%u mtu=%u icmp_csum_valid=%d dst=%u.%u.%u.%u\n", g_out_len, icmp[0], icmp[1],
           icmp[6] << 8 | icmp[7], csum(icmp, g_out_len - 34, 0) == 0, g_out[30], g_out[31], g_out[32], g_out[33]);

    /* VPN kill switch drops off-subnet traffic while the tunnel is down */
    setup();
    vpn_enabled = 1; vpn_killswitch = 1; vpn_route_all = 1; vpn_connected = 0;
    n = build_syn(f, 1460, 443, 0);
    p = mkpbuf(f, n); g_input = p; g_input_freed = 0;
    e = ap_netif_input_hook(p, &nif);
    printf("killswitch err=%d freed=%d\n", e, g_input_freed);

    /* pcap capture through the ring buffer */
    setup();
    mayhem_pcap_teardown();
    mayhem_pcap_setup(PCAP_MODE_PROMISCUOUS, 1);
    n = build_syn(f, 1460, 443, 0);
    p = mkpbuf(f, n);
    ap_netif_linkoutput_hook(&nif, p);
    pbuf_free(p);
    uint8_t rb[256];
    size_t got = ringbuf_read(rb, sizeof(rb), 0);
    printf("pcap captured=%u ringbuf_read=%zu incl_len=%u orig_len=%u first_mac=%02x\n", pcap_get_captured_count(), got,
           rb[8] | rb[9] << 8, rb[12] | rb[13] << 8, rb[16 + 5]);
    mayhem_pcap_teardown();

    /* ring buffer wrap-around */
    ringbuf_init();
    ringbuf_alloc(8);
    uint8_t w1[6] = {1, 2, 3, 4, 5, 6}, r[8];
    ringbuf_write(w1, 6);
    size_t r1 = ringbuf_read(r, 4, 0);
    int w2 = ringbuf_write(w1, 6);
    int w3 = ringbuf_write(w1, 4);
    size_t r2 = ringbuf_read(r, 8, 0);
    printf("ringbuf r1=%zu w2=%d w3=%d r2=%zu data=%u%u%u%u%u%u%u%u dropped=%u\n", r1, w2, w3, r2, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
           ringbuf_get_dropped_count());
    ringbuf_free();
    return 0;
}
