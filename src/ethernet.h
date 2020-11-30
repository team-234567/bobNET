#ifndef ETHERNET_H
#define ETHERNET_H
#define ETH 0x01
#define ARP 0x0806
#define RARP 0x8035
#define REQ 0x01
#define REP 0x02
#define RREQ 0x03
#define RREP 0x04
#define ETH_ALEN 6
#define IPv4 0x0800
#define HLEN 0x06
#define PLEN 0x04
#define SRC 0
#define DST 1
#include <stdint.h>


#pragma pack(push, 1)
struct libnet_ethernet_hdr{
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
};

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t h_src[6];
    uint8_t ip_src[4];
    uint8_t h_dst[6];
    uint8_t ip_dst[4];
};

struct ipv4_hdr{
    unsigned int hdr_len : 4;
    unsigned int version : 4;

    uint8_t tos;
    uint16_t total_len;
    uint16_t ident;
    //unsigned int flag : 3;
    //unsigned int frg_offset : 13 ;
    uint16_t fragment;
    uint8_t ttl;
    uint8_t proto_type;
    uint16_t hdr_checksum;
    uint8_t ip_src[4];
    uint8_t ip_dst[4];
};
struct icmp_hdr{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identif;
    uint16_t seq_num;
};

#pragma pack(pop)

#endif // ETHERNET_H
