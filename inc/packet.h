/*
 * packet.h
 *
 *  Created on: Mar 16, 2012
 *      Author: chenxm
 *      Email: chen_xm@sjtu.edu.cn
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include <sys/types.h>

/* Ethernet header structure */
typedef struct ethernet_header ethhdr;
struct ethernet_header
{
    u_int8_t  ether_dhost[6];        /* Destination addr */
    u_int8_t  ether_shost[6];       /* Source addr */
    u_int16_t ether_type;           /* Packet type */
};

/* vlan header structure */
typedef struct vlan_header vlhdr;
struct vlan_header {
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t vlan_type;    /* has to be 0x8100 */
    u_int16_t pci;          /* priority/cfi/id */
    u_int16_t ether_type;   /* encapsulated type */
#define VLAN_ID_MASK 0x0fff
#define VLAN_ID(vh) (ntohs((vh)->pci) & VLAN_ID_MASK)
};

/* IP header structure */
typedef struct ip_header iphdr;
struct ip_header
{
    u_int8_t ihl:4;
    u_int8_t version:4;
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
#define IP_RF 0x8000            /* Reserved fragment flag */
#define IP_DF 0x4000            /* Dont fragment flag */
#define IP_MF 0x2000            /* More fragments flag */
#define IP_OFFMASK 0x1fff       /* Mask for fragmenting bits */
    u_int8_t ttl;
    u_int8_t protocol;
#define TCP_PRO 0x06
#define UDP_PRO 0x11
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

/* TCP header structure */
typedef struct tcp_header tcphdr;
struct tcp_header
{
    u_int16_t th_sport;     /* Source port */
    u_int16_t th_dport;     /* Destination port */
    u_int32_t th_seq;       /* Sequence number */
    u_int32_t th_ack;       /* Acknowledgement number */
    u_int8_t th_x2:4;       /* (Unused) */
    u_int8_t th_off:4;      /* Data offset */
    u_int8_t th_flags;
#define TH_FIN_MASK 0x01
#define TH_SYN_MASK 0x02
#define TH_RST_MASK 0x04
#define TH_PUSH_MASK 0x08
#define TH_ACK_MASK 0x10
#define TH_URG_MASK 0x20
    u_int16_t th_win;       /* Window */
    u_int16_t th_sum;       /* Checksum */
    u_int16_t th_urp;       /* Urgent pointer */
};

/* UDP header structure */
typedef struct udp_header udphdr;
struct udp_header
{
    u_int16_t uh_sport;     /* Source port */
    u_int16_t uh_dport;     /* Destination port */
    u_int16_t uh_length;
    u_int16_t uh_check;
};

extern void print_as_ethernet_header(char* ptr);
extern void print_as_ip_header(char* ptr);
extern void print_as_tcp_header(char* ptr);

/* parses the SSL header and if the packet is client-Hand-shake, attempts to find
   server-name-extension */
extern int  ssl_find_host_name(const char* ptr, int len, char* host, int hostLen, int* isHelloMessage);

#endif /* __PACKET_H__ */

