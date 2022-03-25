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
    ERR_PP_VERSION             = -1,
    ERR_PP2_SIG                = -2,
    ERR_PP2_VERSION            = -3,
    ERR_PP2_CMD                = -4,
    ERR_PP2_ADDR_FAMILY        = -5,
    ERR_PP2_TRANSPORT_PROTOCOL = -6,
    ERR_PP2_LENGTH             = -7,
    ERR_PP2_IPV4_SRC_IP        = -8,
    ERR_PP2_IPV4_DST_IP        = -9,
    ERR_PP2_IPV6_SRC_IP        = -10,
    ERR_PP2_IPV6_DST_IP        = -11,
    ERR_PP2_TLV_LENGTH         = -12,
    ERR_PP2_TYPE_CRC32C        = -13,
    ERR_PP2_TYPE_SSL           = -14,
    ERR_PP2_TYPE_UNIQUE_ID     = -15,
    ERR_PP2_TYPE_AWS           = -16,
    ERR_PP2_TYPE_AZURE         = -17,
    ERR_PP1_CRLF               = -18,
    ERR_PP1_PROXY              = -19,
    ERR_PP1_SPACE              = -20,
    ERR_PP1_TRANSPORT_FAMILY   = -21,
    ERR_PP1_IPV4_SRC_IP        = -22,
    ERR_PP1_IPV4_DST_IP        = -23,
    ERR_PP1_IPV6_SRC_IP        = -24,
    ERR_PP1_IPV6_DST_IP        = -25,
    ERR_PP1_SRC_PORT           = -26,
    ERR_PP1_DST_PORT           = -27,
    ERR_HEAP_ALLOC             = -28,
};

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

enum
{
    ADDR_FAMILY_UNSPEC,
    ADDR_FAMILY_INET,
    ADDR_FAMILY_INET6,
    ADDR_FAMILY_UNIX,
};

enum
{
    TRANSPORT_PROTOCOL_UNSPEC,
    TRANSPORT_PROTOCOL_STREAM,
    TRANSPORT_PROTOCOL_DGRAM,
};

typedef struct
{
    uint8_t      address_family;
    uint8_t      transport_protocol;
    char         src_addr[108];
    char         dst_addr[108];
    uint16_t     src_port;
    uint16_t     dst_port;
    pp2_info_t   pp2_info;
    tlv_array_t *tlv_array;
} pp_info_t;

/* Returns a descriptive error message
 *
 * error    int32_t value from other API functions
 * return   Pointer to the descriptive message if error value is recognized else NULL
 */
const char *pp_strerror(int32_t error);

/* Searches for the specified TLV and returns its value
 *
 * pp_info  Pointer to a pp_info_t structure used in pp_parse()
 * length   Pointer to a uint16_t where the TLV's value length will be set
 * return   Pointer to a buffer holding the TLV's value if found else NULL.
 *          In case of US-ASCII value the buffer is NULL terminated
 */
const uint8_t *pp_info_get_alpn(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_authority(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_crc32c(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_unique_id(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_version(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_cn(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_cipher(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_sig_alg(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_key_alg(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_ssl_netns(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_aws_vpce_id(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_azure_linkid(const pp_info_t *pp_info, uint16_t *length);

/* Clears the pp_info_t structure and frees any allocated memory associated with it. Shall always be called after a call to pp_parse_hdr()
 *
 * pp_info  Pointer to a filled pp_info_t structure which has been used to a previous call to pp_parse_hdr()
 */
void pp_info_clear(pp_info_t *pp_info);

/* Creates a PROXY protocol header considering the information inside the pp_info.
 *
 * version:     0 Create a v1 PROXY protocol header
 *              1 Create a v2 PROXY protocol header
 * pp_info      Pointer to a filled pp_info_t structure whose information will be used for the creation of the PROXY protocol header
 * pp_hdr_len   Pointer to a uint16_t where the length of the create PROXY protocol header will be set
 * error        Pointer to a uint32_t where the error value will be set
 *                  ERR_NULL No error occurred
 *                  < 0      Error
 * return       Pointer to a heap allocated buffer containing the PROXY protocol header. Must be freed with free()
 */
uint8_t *pp_create_hdr(uint8_t version, const pp_info_t *pp_info, uint16_t *pp_hdr_len, int32_t *error);

/* Inpects the buffer for a PROXY protocol header and extracts all the information if any
 *
 * buffer           Buffer to be inspected and parsed. Typically the buffer given for a read operation
 * buffer_length    Buffer's length. Typically the bytes read from the read operation
 * pp_info          Pointer to a pp_info_t structure which will get filled with all the extracted information
 * return           >  0 Length of the PROXY protocol header
 *                  == 0 No PROXY protocol header found
 *                  <  0 Error occurred. pp_strerror() with that value can be used to get a descriptive message
 */
int32_t pp_parse_hdr(uint8_t *buffer, uint32_t buffer_length, pp_info_t *pp_info);

#endif