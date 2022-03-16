/*
 * c-proxy-protocol is an ANSI C library to parse and create PROXY protocol v1 and v2 headers
 * Copyright (C) 2022  Kosmas Valianos (kosmas.valianos@gmail.com)
 *
 * The c-proxy-protocol library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The c-proxy-protocol library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <stdlib.h>
#include <stdint.h>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
#endif

enum
{
    ERR_NULL,
    ERR_PP_VERSION,
    ERR_PP2_SIG,
    ERR_PP2_VERSION,
    ERR_PP2_CMD,
    ERR_PP2_TRANSPORT_FAMILY,
    ERR_PP2_LENGTH,
    ERR_PP2_IPV4_SRC_IP,
    ERR_PP2_IPV4_DST_IP,
    ERR_PP2_IPV6_SRC_IP,
    ERR_PP2_IPV6_DST_IP,
    ERR_PP2_TLV_LENGTH,
    ERR_PP2_TYPE_CRC32C,
    ERR_PP2_TYPE_UNIQUE_ID,
    ERR_PP2_TYPE_AWS,
    ERR_PP2_TYPE_AZURE,
    ERR_PP1_CRLF,
    ERR_PP1_PROXY,
    ERR_PP1_SPACE,
    ERR_PP1_TRANSPORT_FAMILY,
    ERR_PP1_IPV4_SRC_IP,
    ERR_PP1_IPV4_DST_IP,
    ERR_PP1_IPV6_SRC_IP,
    ERR_PP1_IPV6_DST_IP,
    ERR_PP1_SRC_PORT,
    ERR_PP1_DST_PORT,
};

/* Type-Length-Value (TLV vectors) */
#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_UNIQUE_ID      0x05
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30
/* Custom TLVs */
#define PP2_TYPE_AWS            0xEA
#define PP2_TYPE_AZURE          0xEE

/* PP2_TYPE_SSL subtypes */
#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

/* PP2_TYPE_AWS subtypes */
#define PP2_SUBTYPE_AWS_VPCE_ID 0x01

/* PP2_TYPE_AZURE subtypes */
#define PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID 0x01

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
    uint8_t     v2local; /* Used only in v2. 1: LOCAL 0: PROXY */
    char        src_addr[108];
    char        dst_addr[108];
    uint16_t    src_port;
    uint16_t    dst_port;
    tlv_array_t tlv_array;
} pp_info_t;

const char *pp_strerror(uint32_t error);
uint8_t    *pp_info_get_tlv_value(const pp_info_t *pp_info, uint8_t type, uint8_t subtype, uint16_t *value_len_out);
void        pp_info_clear(pp_info_t *pp_info);

/*
 * version:
 *  v1 : 1
 *  v2 : 2
 * fam - v1:
 *  AF_INET
 *  AF_INET6
 * fam - v2:
 *  \x00 : UNSPEC
 *  \x11 : TCP over IPv4
 *  \x12 : UDP over IPv4
 *  \x21 : TCP over IPv6
 *  \x22 : UDP over IPv6
 *  \x31 : UNIX stream
 *  \x32 : UNIX datagram
 */
uint8_t    *pp_create_hdr(uint8_t version, uint8_t fam, const pp_info_t *pp_info, uint32_t *pp_hdr_len, uint32_t *error);

int         pp_parse(uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info);

#endif