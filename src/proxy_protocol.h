#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
#endif

typedef char ip_str_t[INET6_ADDRSTRLEN];

typedef struct
{
    uint8_t  type;
    uint16_t length;
    uint8_t  value[1];
} tlv_t;

typedef struct
{
    uint32_t  len;  /* Number of elements  */
    uint32_t  size; /* Allocated elements  */
    tlv_t   **tlvs; /* Pointer to tlv_t* elements */
} tlv_array_t;

typedef struct
{
    ip_str_t    src_ip_str;
    uint16_t    src_port;
    ip_str_t    dst_ip_str;
    uint16_t    dst_port;
    tlv_array_t tlv_array;
} pp_info_t;

void     pp_info_clear(pp_info_t* pp_info);
uint8_t *ppv2_create_message(uint8_t fam, const pp_info_t *proxy_info, uint32_t *pp_msg_v2_len, int *error);
char    *ppv1_create_message(uint8_t fam, const pp_info_t *proxy_info, uint32_t *pp_msg_v1_len, int *error);
int      pp_parse(uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info);

#endif