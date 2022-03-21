/*
 * libproxyprotocol is an ANSI C library to parse and create PROXY protocol v1 and v2 headers
 * Copyright (C) 2022  Kosmas Valianos (kosmas.valianos@gmail.com)
 *
 * The libproxyprotocol library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The libproxyprotocol library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <stdint.h>

enum
{
    ERR_NULL,
    ERR_PP_VERSION           = -1,
    ERR_PP2_SIG              = -2,
    ERR_PP2_VERSION          = -3,
    ERR_PP2_CMD              = -4,
    ERR_PP2_TRANSPORT_FAMILY = -5,
    ERR_PP2_LENGTH           = -6,
    ERR_PP2_IPV4_SRC_IP      = -7,
    ERR_PP2_IPV4_DST_IP      = -8,
    ERR_PP2_IPV6_SRC_IP      = -9,
    ERR_PP2_IPV6_DST_IP      = -10,
    ERR_PP2_TLV_LENGTH       = -11,
    ERR_PP2_TYPE_CRC32C      = -12,
    ERR_PP2_TYPE_SSL         = -13,
    ERR_PP2_TYPE_UNIQUE_ID   = -14,
    ERR_PP2_TYPE_AWS         = -15,
    ERR_PP2_TYPE_AZURE       = -16,
    ERR_PP1_CRLF             = -17,
    ERR_PP1_PROXY            = -18,
    ERR_PP1_SPACE            = -19,
    ERR_PP1_TRANSPORT_FAMILY = -20,
    ERR_PP1_IPV4_SRC_IP      = -21,
    ERR_PP1_IPV4_DST_IP      = -22,
    ERR_PP1_IPV6_SRC_IP      = -23,
    ERR_PP1_IPV6_DST_IP      = -24,
    ERR_PP1_SRC_PORT         = -25,
    ERR_PP1_DST_PORT         = -26,
    ERR_HEAP_ALLOC           = -27,
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

/* PP2_TYPE_SSL <client> bit field  */
#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

/* PP2_TYPE_AWS subtypes */
#define PP2_SUBTYPE_AWS_VPCE_ID 0x01

/* PP2_TYPE_AZURE subtypes */
#define PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID 0x01

typedef struct _tlv_array_t tlv_array_t;

typedef struct
{
    uint8_t ssl;                /* 1: client connected over SSL/TLS 0: otherwise */
    uint8_t cert_in_connection; /* 1: client provided a certificate over the current connection 0: otherwise */
    uint8_t cert_in_session;    /* 1: client provided a certificate at least once over the TLS session this connection belongs to 0: otherwise */
    uint8_t cert_verified;      /* 1: client presented a certificate and it was successfully verified 1: otherwise */
} pp2_ssl_info_t;

typedef struct
{
    uint8_t        local; /* 1: LOCAL 0: PROXY */
    pp2_ssl_info_t pp2_ssl_info;
} pp2_info_t;

typedef struct
{
    char         src_addr[108];
    char         dst_addr[108];
    uint16_t     src_port;
    uint16_t     dst_port;
    pp2_info_t   pp2_info;
    tlv_array_t *tlv_array;
} pp_info_t;

const char *pp_strerror(int32_t error);
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

int32_t     pp_parse_hdr(uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info);

#endif