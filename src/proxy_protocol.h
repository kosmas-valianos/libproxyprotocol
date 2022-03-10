#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

typedef char ip_str_t[INET6_ADDRSTRLEN];

typedef struct
{
    ip_str_t  src_ip_str;
    uint16_t  src_port;
    ip_str_t  dst_ip_str;
    uint16_t  dst_port;
} pp_info_t;

uint8_t *ppv2_create_message(uint8_t fam, const pp_info_t *proxy_info, uint32_t *pp_msg_v2_len);
char    *ppv1_create_message(uint8_t fam, const pp_info_t *proxy_info);
bool     pp_parse(const uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info);

#endif