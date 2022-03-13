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

/* Type-Length-Value (TLV vectors) */
#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30
/* Custom TLVs */
#define PP2_TYPE_AWS            0xEA

/* PP2_TYPE_SSL subtypes */
#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

/* PP2_TYPE_AWS subtypes */
#define PP2_SUBTYPE_AWS_VPCE_ID 0x01

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

uint8_t *pp_info_get_tlv_value(const pp_info_t* pp_info, uint8_t type, uint8_t subtype, uint16_t *value_len_out);
void     pp_info_clear(pp_info_t* pp_info);
uint8_t *pp_create_msg(uint8_t version, uint8_t fam, const pp_info_t *pp_info, uint32_t *pp_msg_len, int *error);
int      pp_parse(uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info);

#endif