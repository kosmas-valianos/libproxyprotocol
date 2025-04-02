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
    ERR_PP_VERSION,
    ERR_PP2_SIG,
    ERR_PP2_VERSION,
    ERR_PP2_CMD,
    ERR_PP2_ADDR_FAMILY,
    ERR_PP2_TRANSPORT_PROTOCOL,
    ERR_PP2_LENGTH,
    ERR_PP2_IPV4_SRC_IP,
    ERR_PP2_IPV4_DST_IP,
    ERR_PP2_IPV6_SRC_IP,
    ERR_PP2_IPV6_DST_IP,
    ERR_PP2_TLV_LENGTH,
    ERR_PP2_TYPE_CRC32C,
    ERR_PP2_TYPE_SSL,
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
    ERR_HEAP_ALLOC
};

/* Returns a descriptive error message
 *
 * error    int32_t value from other API functions
 * return   Pointer to the descriptive message if the error value is recognized else NULL
 */
const char *pp_strerror(int32_t error);

typedef struct
{
    uint8_t ssl;                /* 1: client connected over SSL/TLS 0: otherwise */
    uint8_t cert_in_connection; /* 1: client provided a certificate over the current connection 0: otherwise */
    uint8_t cert_in_session;    /* 1: client provided a certificate at least once over the TLS session this connection belongs to 0: otherwise */
    uint8_t cert_verified;      /* 1: client presented a certificate and it was successfully verified 0: otherwise */
} pp2_ssl_info_t;

typedef struct _pp2_tlv_t pp2_tlv_t;

typedef struct
{
    uint32_t    len;  /* Number of elements  */
    uint32_t    size; /* Allocated elements  */
    pp2_tlv_t **tlvs; /* Pointer to pp2_tlv_t* elements */
} tlv_array_t;

typedef struct
{
    uint8_t local;  /* 1: LOCAL 0: PROXY */
    /*
     * In creation
     *      > 1: The power of 2 in which the header will be aligned using a NOOP TLV.
     *           Example: 2 => 2^2 => 4 => Append enough bytes to the header using the NOOP TLV so that size_of_hdr % 4 becomes 0
     *      <= 1: No alignment, padding
     * In parsing:
     *      Ignored
     */
    uint8_t        alignment_power;
    pp2_ssl_info_t pp2_ssl_info;
    tlv_array_t    tlv_array;
    /*
     * In creation:
     *      1: calculate and add crc32c checksum TLV
     *      0: no crc32c checksum
     * In parsing:
     *      1: crc32c checksum TLV is present and verified. Optionally, pp_info_get_crc32c() can be used to get the value
     *      0: crc32c checksum is not present
     */
    uint8_t crc32c;
} pp2_info_t;

enum
{
    ADDR_FAMILY_UNSPEC,
    ADDR_FAMILY_INET,
    ADDR_FAMILY_INET6,
    ADDR_FAMILY_UNIX
};

enum
{
    TRANSPORT_PROTOCOL_UNSPEC,
    TRANSPORT_PROTOCOL_STREAM,
    TRANSPORT_PROTOCOL_DGRAM
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
} pp_info_t;


/* Adds the specified TLV in the given pp_info
 *
 * pp_info          Pointer to a pp_info_t structure to be used in pp_create_hdr()
 * length           The length of the TLV's value in case it is not a US-ASCII value
 * $value_param(s)  The value(s) of the specified TLV
 * return           1: success 0: failure
 */
uint8_t pp_info_add_alpn(pp_info_t *pp_info, uint16_t length, const uint8_t *alpn);
uint8_t pp_info_add_authority(pp_info_t *pp_info, uint16_t length, const uint8_t *host_name);
uint8_t pp_info_add_unique_id(pp_info_t *pp_info, uint16_t length, const uint8_t *unique_id);
uint8_t pp_info_add_ssl(pp_info_t *pp_info, const char *version, const char *cipher, const char *sig_alg, const char *key_alg, const uint8_t *cn, uint16_t cn_len);
uint8_t pp_info_add_netns(pp_info_t *pp_info, const char *netns);
uint8_t pp_info_add_aws_vpce_id(pp_info_t *pp_info, const char *vpce_id);
uint8_t pp_info_add_azure_linkid(pp_info_t *pp_info, uint32_t linkid);

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
const uint8_t *pp_info_get_netns(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_aws_vpce_id(const pp_info_t *pp_info, uint16_t *length);
const uint8_t *pp_info_get_azure_linkid(const pp_info_t *pp_info, uint16_t *length);

/* Clears the pp_info_t structure and frees any allocated memory associated with it
 * Parsing: Always call it after pp_parse_hdr()
 * Creating: Always call it after pp_create_hdr() or failure in pp_info_add_*() functions
 *
 * In case it is forgotten and the parsing/creation is about a v2 PROXY protocol header with TLVs, memory leaks will appear!
 *
 * pp_info  Parsing: Pointer to a filled pp_info_t structure which has been used to a previous call to pp_parse_hdr()
 *          Creating: Pointer to an initialized pp_info_t structure in which pp_info_add_*() functions have been used
 */
void pp_info_clear(pp_info_t *pp_info);

/* Helper to easily create a v2 healthcheck PROXY protocol header.
 *
 * Note: There is not an equivalent v1 function because specification 2.6 suggests that senders
 *       SHOULD build a valid PROXY line i.e. usage of "UNKNOWN" style is discouraged 
 * 
 * pp_hdr_len   Pointer to a uint16_t where the length of the create PROXY protocol header will be set
 * error        Pointer to a int32_t where the error value will be set
 *                  ERR_NULL No error occurred
 *                  < 0      Error occurred. Optionally, pp_strerror() with that value can be used to get a descriptive message
 * return       Pointer to a heap allocated buffer containing the PROXY protocol header. Must be freed with free()
 */
uint8_t *pp2_create_healthcheck_hdr(uint16_t *pp2_hdr_len, int32_t *error);

/* Creates a PROXY protocol header considering the information inside the pp_info.
 *
 * version:     1 Create a v1 PROXY protocol header
 *              2 Create a v2 PROXY protocol header
 * pp_info      Pointer to a filled pp_info_t structure whose information will be used for the creation of the PROXY protocol header
 * pp_hdr_len   Pointer to a uint16_t where the length of the create PROXY protocol header will be set
 * error        Pointer to a int32_t where the error value will be set
 *                  ERR_NULL No error occurred
 *                  < 0      Error occurred. Optionally, pp_strerror() with that value can be used to get a descriptive message
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
 *                  <  0 Error occurred. Optionally, pp_strerror() with that value can be used to get a descriptive message
 */
int32_t pp_parse_hdr(uint8_t *buffer, uint32_t buffer_length, pp_info_t *pp_info);

#endif
