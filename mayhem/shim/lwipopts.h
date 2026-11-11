/* Minimal lwIP options for building the unmodified router sources on a Linux host. */
#ifndef MAYHEM_LWIPOPTS_H
#define MAYHEM_LWIPOPTS_H

#define NO_SYS                  1
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define LWIP_IPV4               1
#define LWIP_IPV6               0
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_ICMP               1
#define LWIP_ARP                1
#define LWIP_DNS                0
#define LWIP_DHCP               0
#define LWIP_AUTOIP             0
#define LWIP_IGMP               0
#define MEM_ALIGNMENT           4
#define LWIP_NETIF_API          0
#define LWIP_STATS              0
#define LWIP_PROVIDE_ERRNO      1

#endif
