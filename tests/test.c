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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include "../src/proxy_protocol.h"

#define NUM_ELEMS(array) (uint32_t)(sizeof(array) / sizeof(array[0]))

/* Type-Length-Value (TLV vectors) */
/* They need to be defined, for tests purposes, as the API does not expose them */
#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_UNIQUE_ID      0x05
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION     0x21
#define PP2_SUBTYPE_SSL_CN          0x22
#define PP2_SUBTYPE_SSL_CIPHER      0x23
#define PP2_SUBTYPE_SSL_SIG_ALG     0x24
#define PP2_SUBTYPE_SSL_KEY_ALG     0x25
#define PP2_SUBTYPE_SSL_GROUP       0x26
#define PP2_SUBTYPE_SSL_SIG_SCHEME  0x27
#define PP2_SUBTYPE_SSL_CLIENT_CERT 0x28
#define PP2_TYPE_NETNS          0x30
/* Custom TLVs */
#define PP2_TYPE_AWS            0xEA
#define PP2_TYPE_AZURE          0xEE

/* PP2_TYPE_AWS subtypes */
#define PP2_SUBTYPE_AWS_VPCE_ID 0x01

/* PP2_TYPE_AZURE subtypes */
#define PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID 0x01

typedef struct
{
    uint8_t  type;
    uint8_t  subtype;
    uint16_t value_len;
    const uint8_t *value;
} test_tlv_t;

typedef struct
{
    const char    *name;
    uint8_t        version;
    uint8_t        create_healthcheck;
    pp_info_t      pp_info_in;
    const uint8_t *raw_bytes_in;
    uint32_t       raw_bytes_in_length;
    int32_t        error_expected; /* error parameter of pp_create_hdr() */
    int32_t        rc_expected;
    pp_info_t      pp_info_out_expected;
    test_tlv_t     add_tlvs[10];
    test_tlv_t     expected_tlvs[10];
} test_t;

uint8_t pp2_hdr_vpce[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of v2 signature */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of v2 signature */
            0x21, 0x11, 0x00, 0x40, /* ver_cmd, fam and len */
            0xc0, 0xa8, 0x0a, 0x64, /* Source IP */
            0xc0, 0xa8, 0x0b, 0x5a, /* Destination IP */
            0xa5, 0x5c, 0x1f, 0x90, /* Source port, Destination port */
            0x03, 0x00, 0x04, 0xe5, /* CRC32C TLV start */
            0x18, 0x86, 0xf8, 0xea, /* CRC32C TLV end, AWS VPCE ID TLV start */
            0x00, 0x17, 0x01, 0x76,
            0x70, 0x63, 0x65, 0x2d,
            0x32, 0x33, 0x64, 0x38,
            0x65, 0x7a, 0x6a, 0x6b,
            0x33, 0x38, 0x62, 0x63,
            0x68, 0x69, 0x6c, 0x6d,
            0x34, 0x04, 0x00, 0x10, /* AWS VPCE ID TLV end, NOOP TLV start */
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, /* NOOP TLV end */
};

/* Self-signed EC (prime256v1) X.509 DER certificate, CN=test */
uint8_t test_client_cert_der[] = {
    0x30, 0x82, 0x01, 0x72, 0x30, 0x82, 0x01, 0x19, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x27, 0xd1, 0xb7, 0x26, 0x8d, 0xd6, 0x95, 0x5b, 0xda,
    0xe3, 0x58, 0x8d, 0x19, 0xbe, 0x88, 0x84, 0x32, 0xcc, 0x62, 0xea, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04,
    0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x33,
    0x31, 0x31, 0x31, 0x34, 0x34, 0x36, 0x34, 0x39, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x30, 0x33, 0x30, 0x38, 0x31, 0x34, 0x34, 0x36, 0x34, 0x39, 0x5a,
    0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x04, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x88, 0x7b, 0xd1, 0x60,
    0x92, 0x37, 0x00, 0x86, 0x8c, 0x3d, 0x06, 0x42, 0xf4, 0x1b, 0x9f, 0x27,
    0x9e, 0xca, 0x74, 0xc5, 0xdb, 0xfd, 0x6f, 0x82, 0x39, 0x61, 0x70, 0xb9,
    0x0b, 0xe8, 0x14, 0x07, 0xc6, 0x30, 0xea, 0xd8, 0xbb, 0x01, 0x05, 0x5f,
    0x07, 0x6a, 0xe8, 0x1f, 0x2c, 0x4b, 0x43, 0x8f, 0x4d, 0x87, 0xa1, 0xad,
    0xc6, 0x19, 0x05, 0xae, 0x2b, 0x09, 0x60, 0x55, 0x00, 0x4a, 0xe7, 0xb4,
    0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0xf9, 0x84, 0xb4, 0x02, 0xba, 0x3c, 0xa8, 0xa9, 0x19,
    0x86, 0x9e, 0x3c, 0xe6, 0x77, 0x79, 0x39, 0x9a, 0x7f, 0x1e, 0x53, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0xf9, 0x84, 0xb4, 0x02, 0xba, 0x3c, 0xa8, 0xa9, 0x19, 0x86, 0x9e, 0x3c,
    0xe6, 0x77, 0x79, 0x39, 0x9a, 0x7f, 0x1e, 0x53, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x2a, 0x7e, 0xf8, 0xf6,
    0x4c, 0x99, 0x27, 0x70, 0x24, 0x9b, 0x51, 0x8f, 0x29, 0x23, 0x9b, 0x41,
    0x01, 0x93, 0x0f, 0x77, 0x84, 0xba, 0x08, 0x34, 0xee, 0x23, 0xa6, 0xaf,
    0xe5, 0xdc, 0x7d, 0xf3, 0x02, 0x20, 0x53, 0xf2, 0x42, 0xd6, 0xab, 0xca,
    0x9a, 0x66, 0xfe, 0x3e, 0x49, 0x77, 0xf6, 0xe4, 0xea, 0xcb, 0xff, 0xde,
    0x1e, 0xf7, 0x2b, 0x97, 0x40, 0x99, 0xde, 0x2e, 0x9b, 0x15, 0x5c, 0x87,
    0xb7, 0x7c
};

uint8_t pp2_hdr_ssl[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of v2 signature */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of v2 signature */
            0x21, 0x11, 0x00, 0x64, /* ver_cmd, fam and len */
            0xc0, 0xa8, 0x0a, 0x64, /* Source IP */
            0xc0, 0xa8, 0x0b, 0x5a, /* Destination IP */
            0xa5, 0x5c, 0x1f, 0x90, /* Source port, Destination port */
            0x20, 0x00, 0x4e, 0x07, /* PP2_TYPE_SSL begin */
            0x00, 0x00, 0x00, 0x00,
            0x21, 0x00, 0x07, 0x54, /* PP2_SUBTYPE_SSL_VERSION begin */
            0x4c, 0x53, 0x76, 0x31,
            0x2e, 0x32, 0x22, 0x00, /* PP2_SUBTYPE_SSL_VERSION end, PP2_SUBTYPE_SSL_CN begin */
            0x0b, 0x65, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65,
            0x2e, 0x63, 0x6f, 0x6d, /* PP2_SUBTYPE_SSL_CN end */
            0x23, 0x00, 0x1b, 0x45, /* PP2_SUBTYPE_SSL_CIPHER begin */
            0x43, 0x44, 0x48, 0x45,
            0x2d, 0x52, 0x53, 0x41,
            0x2d, 0x41, 0x45, 0x53,
            0x31, 0x32, 0x38, 0x2d,
            0x47, 0x43, 0x4d, 0x2d,
            0x53, 0x48, 0x41, 0x32,
            0x35, 0x36, 0x24, 0x00, /* PP2_SUBTYPE_SSL_CIPHER end, PP2_SUBTYPE_SSL_SIG_ALG begin */
            0x06, 0x53, 0x48, 0x41,
            0x32, 0x35, 0x36, 0x25, /* PP2_SUBTYPE_SSL_SIG_ALG end, PP2_SUBTYPE_SSL_KEY_ALG begin */
            0x00, 0x07, 0x52, 0x53,
            0x41, 0x32, 0x30, 0x34,
            0x38, 0x04, 0x00, 0x04, /* PP2_SUBTYPE_SSL_KEY_ALG end, PP2_SUBTYPE_SSL_VERSION end, PP2_TYPE_NOOP begin */
            0x00, 0x00, 0x00, 0x00  /* PP2_TYPE_NOOP end */
};

static const uint32_t test_azure_linkid = 5678;

/* v2 header with TLV length 0xFFFD (65533) causing uint16_t overflow in TLV offset calculation */
uint8_t pp2_hdr_tlv_overflow[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of v2 signature */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of v2 signature */
            0x21, 0x11, 0x00, 0x10, /* ver_cmd, fam and len (16) */
            0xc0, 0xa8, 0x0a, 0x64, /* Source IP */
            0xc0, 0xa8, 0x0b, 0x5a, /* Destination IP */
            0xa5, 0x5c, 0x1f, 0x90, /* Source port, Destination port */
            0x01, 0xff, 0xfd, 0x00, /* PP2_TYPE_ALPN TLV with length 0xFFFD, 1 byte value */
};

/* v2 header with PP2_TYPE_SSL TLV too short (length 2, needs at least 5) */
uint8_t pp2_hdr_ssl_too_short[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of v2 signature */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of v2 signature */
            0x21, 0x11, 0x00, 0x11, /* ver_cmd, fam and len (17) */
            0xc0, 0xa8, 0x0a, 0x64, /* Source IP */
            0xc0, 0xa8, 0x0b, 0x5a, /* Destination IP */
            0xa5, 0x5c, 0x1f, 0x90, /* Source port, Destination port */
            0x20, 0x00, 0x02,       /* PP2_TYPE_SSL TLV with length 2 */
            0x00, 0x00,             /* Truncated SSL data (too short) */
};

/* v2 header with PP2_TYPE_SSL sub-TLV trailing bytes (1 valid sub-TLV + 2 orphan bytes) */
uint8_t pp2_hdr_ssl_trailing_bytes[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of v2 signature */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of v2 signature */
            0x21, 0x11, 0x00, 0x1c, /* ver_cmd, fam and len (28) */
            0xc0, 0xa8, 0x0a, 0x64, /* Source IP */
            0xc0, 0xa8, 0x0b, 0x5a, /* Destination IP */
            0xa5, 0x5c, 0x1f, 0x90, /* Source port, Destination port */
            0x20, 0x00, 0x0d,       /* PP2_TYPE_SSL TLV with length 13 */
            0x01,                   /* client (PP2_CLIENT_SSL set) */
            0x00, 0x00, 0x00, 0x00, /* verify (0 = verified) */
            0x21, 0x00, 0x03,       /* PP2_SUBTYPE_SSL_VERSION, length 3 */
            0x31, 0x2e, 0x32,       /* "1.2" */
            0xff, 0xff,             /* 2 trailing orphan bytes (not a valid sub-TLV header) */
};

static uint8_t pp_add_tlvs(pp_info_t *pp_info, const test_tlv_t (*add_tlvs)[10])
{
    uint8_t i;
    uint8_t rc = 1;
    uint32_t azure_linkid = 0;
    uint16_t ssl_cn_len = 0;
    uint16_t ssl_client_cert_len = 0;
    const uint8_t *ssl_cn = NULL;
    const uint8_t *ssl_client_cert = NULL;
    const char *ssl_version = NULL;
    const char *ssl_cipher = NULL;
    const char *ssl_sig_alg = NULL;
    const char *ssl_key_alg = NULL;
    const char *ssl_group = NULL;
    const char *ssl_sig_scheme = NULL;
    for (i = 0; i < NUM_ELEMS(*add_tlvs) && rc == 1; i++)
    {
        const test_tlv_t *test_tlv = &(*add_tlvs)[i];
        if (test_tlv->type)
        {
            switch (test_tlv->type)
            {
            case PP2_TYPE_ALPN:
                rc = pp_info_add_alpn(pp_info, test_tlv->value_len, test_tlv->value);
                break;
            case PP2_TYPE_AUTHORITY:
                rc = pp_info_add_authority(pp_info, test_tlv->value_len, test_tlv->value);
                break;
            case PP2_TYPE_UNIQUE_ID:
                rc = pp_info_add_unique_id(pp_info, test_tlv->value_len, test_tlv->value);
                break;
            case PP2_SUBTYPE_SSL_VERSION:
                ssl_version = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_CN:
                ssl_cn_len = test_tlv->value_len;
                ssl_cn = test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_CIPHER:
                ssl_cipher = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_SIG_ALG:
                ssl_sig_alg = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_KEY_ALG:
                ssl_key_alg = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_GROUP:
                ssl_group = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_SIG_SCHEME:
                ssl_sig_scheme = (const char*) test_tlv->value;
                break;
            case PP2_SUBTYPE_SSL_CLIENT_CERT:
                ssl_client_cert_len = test_tlv->value_len;
                ssl_client_cert = test_tlv->value;
                break;
            case PP2_TYPE_NETNS:
                rc = pp_info_add_netns(pp_info, (const char*) test_tlv->value);
                break;
            case PP2_TYPE_AWS:
                rc = pp_info_add_aws_vpce_id(pp_info, (const char*) test_tlv->value);
                break;
            case PP2_TYPE_AZURE:
                memcpy(&azure_linkid, (const uint32_t*) test_tlv->value, sizeof(uint32_t));
                rc = pp_info_add_azure_linkid(pp_info, azure_linkid);
                break;
            default:
                break;
            }
        }
    }

    if (!rc)
    {
        return rc;
    }

    if (pp_info->pp2_info.pp2_ssl_info.ssl)
    {
        rc = pp_info_add_ssl(pp_info, ssl_version, ssl_cipher, ssl_sig_alg, ssl_key_alg, ssl_group, ssl_sig_scheme, ssl_cn, ssl_cn_len, ssl_client_cert, ssl_client_cert_len);
    }

    return rc;
}

static uint8_t pp_verify_tlvs(const pp_info_t *pp_info, const test_tlv_t (*expected_tlvs)[10])
{
    uint8_t i;
    for (i = 0; i < NUM_ELEMS(*expected_tlvs); i++)
    {
        const test_tlv_t *test_tlv = &(*expected_tlvs)[i];
        if (test_tlv->type)
        {
            uint16_t tlv_value_len = 0;
            const uint8_t *tlv_value = NULL;
            switch (test_tlv->type)
            {
            case PP2_TYPE_ALPN:
                tlv_value = pp_info_get_alpn(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_AUTHORITY:
                tlv_value = pp_info_get_authority(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_CRC32C:
                tlv_value = pp_info_get_crc32c(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_NOOP:
                break;
            case PP2_TYPE_UNIQUE_ID:
                tlv_value = pp_info_get_unique_id(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_VERSION:
                tlv_value = pp_info_get_ssl_version(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_CN:
                tlv_value = pp_info_get_ssl_cn(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_CIPHER:
                tlv_value = pp_info_get_ssl_cipher(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_SIG_ALG:
                tlv_value = pp_info_get_ssl_sig_alg(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_KEY_ALG:
                tlv_value = pp_info_get_ssl_key_alg(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_GROUP:
                tlv_value = pp_info_get_ssl_group(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_SIG_SCHEME:
                tlv_value = pp_info_get_ssl_sig_scheme(pp_info, &tlv_value_len);
                break;
            case PP2_SUBTYPE_SSL_CLIENT_CERT:
                tlv_value = pp_info_get_ssl_client_cert(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_NETNS:
                tlv_value = pp_info_get_netns(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_AWS:
                tlv_value = pp_info_get_aws_vpce_id(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_AZURE:
            {
                uint32_t linkid_expected, linkid_got;
                tlv_value = pp_info_get_azure_linkid(pp_info, &tlv_value_len);
                if (!tlv_value)
                {
                    return 0;
                }
                memcpy(&linkid_got, tlv_value, sizeof(uint32_t));
                memcpy(&linkid_expected, test_tlv->value, sizeof(uint32_t));
                if (linkid_got != linkid_expected)
                {
                    return 0;
                }
                continue;
            }
            default:
                break;
            }
            if (!tlv_value || tlv_value_len != test_tlv->value_len || memcmp(tlv_value, test_tlv->value, tlv_value_len))
            {
                return 0;
            }
        }
    }
    return 1;
}

static uint8_t pp_info_equal(const pp_info_t *pp_info_a, const pp_info_t *pp_info_b)
{
    if (pp_info_a->address_family != pp_info_b->address_family)
    {
        return 0;
    }
    if (pp_info_a->transport_protocol != pp_info_b->transport_protocol)
    {
        return 0;
    }
    if (strcmp(pp_info_a->src_addr, pp_info_b->src_addr))
    {
        return 0;
    }
    if (strcmp(pp_info_a->dst_addr, pp_info_b->dst_addr))
    {
        return 0;
    }
    if (pp_info_a->src_port != pp_info_b->src_port)
    {
        return 0;
    }
    if (pp_info_a->dst_port != pp_info_b->dst_port)
    {
        return 0;
    }
    if (pp_info_a->pp2_info.local != pp_info_b->pp2_info.local)
    {
        return 0;
    }
    if (memcmp(&pp_info_a->pp2_info.pp2_ssl_info, &pp_info_b->pp2_info.pp2_ssl_info, sizeof(pp2_ssl_info_t)))
    {
        return 0;
    }
    if (pp_info_a->pp2_info.crc32c != pp_info_b->pp2_info.crc32c)
    {
        return 0;
    }
    return 1;
}

int main(void)
{
    /* Define tests */
    test_t tests[] = {
        {
            .name = "v1 PROXY protocol header: UNKNOWN - short",
            .raw_bytes_in = (const uint8_t*) "PROXY UNKNOWN\r\n",
            .raw_bytes_in_length = (uint32_t) strlen((const char*) tests[0].raw_bytes_in),
            .rc_expected = (int32_t) strlen((const char*) tests[0].raw_bytes_in),
        },
        {
            .name = "v1 PROXY protocol header: UNKNOWN - full",
            .raw_bytes_in = (const uint8_t*) "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            .raw_bytes_in_length = (uint32_t) strlen((const char*) tests[1].raw_bytes_in),
            .rc_expected = (int32_t) strlen((const char*) tests[1].raw_bytes_in),
        },
        {
            .name = "v2 PROXY protocol header: PROXY, TCP over IPv4. TLVs: PP2_TYPE_CRC32C, PP2_TYPE_AWS(PP2_SUBTYPE_AWS_VPCE_ID)",
            .raw_bytes_in = pp2_hdr_vpce,
            .raw_bytes_in_length = sizeof(pp2_hdr_vpce),
            .rc_expected = sizeof(pp2_hdr_vpce),
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = { .crc32c = 1 }
            },
            .expected_tlvs = {
                {
                    .type = PP2_TYPE_CRC32C,
                    .value_len = 4,
                    .value = (const uint8_t*) "\xe5\x18\x86\xf8"
                },
                {
                    .type = PP2_TYPE_AWS,
                    .subtype = PP2_SUBTYPE_AWS_VPCE_ID,
                    .value_len = 23,
                    .value = (const uint8_t*) "vpce-23d8ezjk38bchilm4"
                },
            },
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, TCP over IPv4",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "10.10.1.100",
                .dst_addr = "10.10.2.100",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[3].pp_info_in,
        },
        {
            .name = "v1 PROXY protocol header: create and parse- TCP4",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "10.10.1.100",
                .dst_addr = "10.10.2.100",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[4].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, UNIX stream",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_UNIX,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "/tmp/testsocket1.socket",
                .dst_addr = "/tmp/testsocket2.socket",
            },
            .pp_info_out_expected = tests[5].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: create and parse - LOCAL, AF_UNSPEC",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_UNSPEC,
                .transport_protocol = TRANSPORT_PROTOCOL_UNSPEC,
                .pp2_info.local = 1
            },
            .pp_info_out_expected = tests[6].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, TCP over IPv6",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "fd00:dead:beef::2",
                .dst_addr = "fd00:beef:dead::3",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[7].pp_info_in,
        },
        {
            .name = "v1 PROXY protocol header: create and parse - TCP6",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "fd00:dead:beef::2",
                .dst_addr = "fd00:beef:dead::3",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[8].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, TCP over IPv4. Aligned, padded. TLVs: "
                    "PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN, PP2_SUBTYPE_SSL_CIPHER,"
                    "PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG, PP2_TYPE_AWS(PP2_SUBTYPE_AWS_VPCE_ID), PP2_TYPE_CRC32C",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = {
                    .alignment_power = 2,
                    .pp2_ssl_info = {
                        .ssl = 1,
                        .cert_in_connection = 1,
                        .cert_in_session = 1,
                        .cert_verified = 1,
                    },
                    .crc32c = 1
                }
            },
            .add_tlvs = {
                {
                .type = PP2_SUBTYPE_SSL_VERSION,
                    .value_len = 8,
                    .value = (const uint8_t*) "TLSv1.2"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CN,
                    .value_len = 18,
                    .value = (const uint8_t*) "proxy-protocol.com"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CIPHER,
                    .value_len = 28,
                    .value = (const uint8_t*) "ECDHE-RSA-AES128-GCM-SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_SIG_ALG,
                    .value_len = 7,
                    .value = (const uint8_t*) "SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_KEY_ALG,
                    .value_len = 8,
                    .value = (const uint8_t*) "RSA2048"
                },
                {
                    .type = PP2_TYPE_AWS,
                    .subtype = PP2_SUBTYPE_AWS_VPCE_ID,
                    .value_len = 24,
                    .value = (const uint8_t*) "vpce-24d8ezjk38bchilm4m"
                },
                {
                    .type = PP2_TYPE_CRC32C,
                    .value_len = 4,
                    .value = (const uint8_t*) "\x43\x84\x86\x4e"
                },
            },
            .pp_info_out_expected = tests[9].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: PROXY, TCP over IPv4. TLVs: "
                    "PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN, PP2_SUBTYPE_SSL_CIPHER, PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG",
            .raw_bytes_in = pp2_hdr_ssl,
            .raw_bytes_in_length = sizeof(pp2_hdr_ssl),
            .rc_expected = sizeof(pp2_hdr_ssl),
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = {
                    .pp2_ssl_info = {
                        .ssl = 1,
                        .cert_in_connection = 1,
                        .cert_in_session = 1,
                        .cert_verified = 1
                    }
                }
            },
            .expected_tlvs = {
                {
                    .type = PP2_SUBTYPE_SSL_VERSION,
                    .value_len = 8,
                    .value = (const uint8_t*) "TLSv1.2"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CN,
                    .value_len = 11,
                    .value = (const uint8_t*) "example.com"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CIPHER,
                    .value_len = 28,
                    .value = (const uint8_t*) "ECDHE-RSA-AES128-GCM-SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_SIG_ALG,
                    .value_len = 7,
                    .value = (const uint8_t*) "SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_KEY_ALG,
                    .value_len = 8,
                    .value = (const uint8_t*) "RSA2048"
                },
            },
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, TCP over IPv4. TLVs: "
                    "PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN, PP2_SUBTYPE_SSL_CIPHER, "
                    "PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG, PP2_SUBTYPE_SSL_GROUP, "
                    "PP2_SUBTYPE_SSL_SIG_SCHEME, PP2_SUBTYPE_SSL_CLIENT_CERT",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = {
                    .pp2_ssl_info = {
                        .ssl = 1,
                        .cert_in_connection = 1,
                        .cert_in_session = 1,
                        .cert_verified = 1,
                    },
                    .crc32c = 1
                }
            },
            .add_tlvs = {
                {
                    .type = PP2_SUBTYPE_SSL_VERSION,
                    .value_len = 8,
                    .value = (const uint8_t*) "TLSv1.3"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CN,
                    .value_len = 18,
                    .value = (const uint8_t*) "proxy-protocol.com"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CIPHER,
                    .value_len = 23,
                    .value = (const uint8_t*) "TLS_AES_256_GCM_SHA384"
                },
                {
                    .type = PP2_SUBTYPE_SSL_SIG_ALG,
                    .value_len = 7,
                    .value = (const uint8_t*) "SHA384"
                },
                {
                    .type = PP2_SUBTYPE_SSL_KEY_ALG,
                    .value_len = 8,
                    .value = (const uint8_t*) "RSA4096"
                },
                {
                    .type = PP2_SUBTYPE_SSL_GROUP,
                    .value_len = 10,
                    .value = (const uint8_t*) "secp256r1"
                },
                {
                    .type = PP2_SUBTYPE_SSL_SIG_SCHEME,
                    .value_len = 20,
                    .value = (const uint8_t*) "rsa_pss_rsae_sha256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CLIENT_CERT,
                    .value_len = sizeof(test_client_cert_der),
                    .value = test_client_cert_der
                },
            },
            .pp_info_out_expected = tests[11].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: create and parse - PROXY, TCP over IPv4. TLVs: "
                    "PP2_TYPE_ALPN, PP2_TYPE_AUTHORITY, PP2_TYPE_UNIQUE_ID, PP2_TYPE_NETNS, PP2_TYPE_AZURE",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = {
                    .crc32c = 1
                }
            },
            .add_tlvs = {
                {
                    .type = PP2_TYPE_ALPN,
                    .value_len = 3,
                    .value = (const uint8_t*) "\x02h2"
                },
                {
                    .type = PP2_TYPE_AUTHORITY,
                    .value_len = 18,
                    .value = (const uint8_t*) "proxy-protocol.dev"
                },
                {
                    .type = PP2_TYPE_UNIQUE_ID,
                    .value_len = 8,
                    .value = (const uint8_t*) "\x01\x02\x03\x04\x05\x06\x07\x08"
                },
                {
                    .type = PP2_TYPE_NETNS,
                    .value_len = 8,
                    .value = (const uint8_t*) "mynetns"
                },
                {
                    .type = PP2_TYPE_AZURE,
                    .value_len = 4,
                    .value = (const uint8_t*) &test_azure_linkid
                },
            },
            .pp_info_out_expected = tests[12].pp_info_in,
        },
        {
            .name = "v1 PROXY protocol header: create and parse - AF_UNSPEC",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_UNSPEC,
                .transport_protocol = TRANSPORT_PROTOCOL_UNSPEC,
            },
            .pp_info_out_expected = tests[13].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: pp2_create_healthcheck_hdr() and parse - LOCAL, AF_UNSPEC",
            .create_healthcheck = 1,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_UNSPEC,
                .transport_protocol = TRANSPORT_PROTOCOL_UNSPEC,
                .pp2_info.local = 1
            },
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_TRANSPORT_FAMILY",
            .version = 1,
            .pp_info_in = {
                .transport_protocol = 3,
            },
            .error_expected = -ERR_PP1_TRANSPORT_FAMILY,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_TRANSPORT_FAMILY",
            .version = 1,
            .pp_info_in = {
                .address_family = 3,
            },
            .error_expected = -ERR_PP1_TRANSPORT_FAMILY,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_IPV4_SRC_IP",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "255.255.255.255.255",
            },
            .error_expected = -ERR_PP1_IPV4_SRC_IP,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_IPV4_DST_IP",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "255.255.255.255",
                .dst_addr = "255.255.255.255.255",
            },
            .error_expected = -ERR_PP1_IPV4_DST_IP,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_IPV6_SRC_IP",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            },
            .error_expected = -ERR_PP1_IPV6_SRC_IP,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_IPV6_DST_IP",
            .version = 1,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                .dst_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            },
            .error_expected = -ERR_PP1_IPV6_DST_IP,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_CMD",
            .version = 2,
            .pp_info_in = {
                .pp2_info.local = 0,
            },
            .error_expected = -ERR_PP2_CMD,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_ADDR_FAMILY",
            .version = 2,
            .pp_info_in = {
                .address_family = 4,
            },
            .error_expected = -ERR_PP2_ADDR_FAMILY,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_TRANSPORT_PROTOCOL",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_UNSPEC,
                .pp2_info.local = 1,
                .transport_protocol = 4,
            },
            .error_expected = -ERR_PP2_TRANSPORT_PROTOCOL,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_IPV4_SRC_IP",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "255.255.255.255.255",
            },
            .error_expected = -ERR_PP2_IPV4_SRC_IP,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_IPV4_DST_IP",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "255.255.255.255",
                .dst_addr = "255.255.255.255.255",
            },
            .error_expected = -ERR_PP2_IPV4_DST_IP,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_IPV6_SRC_IP",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            },
            .error_expected = -ERR_PP2_IPV6_SRC_IP,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_IPV6_DST_IP",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_INET6,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                .dst_addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            },
            .error_expected = -ERR_PP2_IPV6_DST_IP,
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_TLV_LENGTH (TLV length overflow)",
            .raw_bytes_in = pp2_hdr_tlv_overflow,
            .raw_bytes_in_length = sizeof(pp2_hdr_tlv_overflow),
            .rc_expected = -ERR_PP2_TLV_LENGTH,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
            },
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_TYPE_SSL (SSL TLV too short)",
            .raw_bytes_in = pp2_hdr_ssl_too_short,
            .raw_bytes_in_length = sizeof(pp2_hdr_ssl_too_short),
            .rc_expected = -ERR_PP2_TYPE_SSL,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
            },
        },
        {
            .name = "v2 PROXY protocol header: -ERR_PP2_TYPE_SSL (SSL sub-TLV trailing bytes)",
            .raw_bytes_in = pp2_hdr_ssl_trailing_bytes,
            .raw_bytes_in_length = sizeof(pp2_hdr_ssl_trailing_bytes),
            .rc_expected = -ERR_PP2_TYPE_SSL,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "192.168.10.100",
                .dst_addr = "192.168.11.90",
                .src_port = 42332,
                .dst_port = 8080,
                .pp2_info = {
                    .pp2_ssl_info = {
                        .ssl = 1,
                        .cert_verified = 1,
                    },
                },
            },
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_TRANSPORT_FAMILY (invalid family, 15-byte header)",
            .raw_bytes_in = (const uint8_t*) "PROXY XXXXXXX\r\n",
            .raw_bytes_in_length = 15,
            .rc_expected = -ERR_PP1_TRANSPORT_FAMILY,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_CRLF (buffer >= 108 bytes, no CRLF)",
            .raw_bytes_in = (const uint8_t*)
                            "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 "  /* 55 */
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",    /* 53, total 108 */
            .raw_bytes_in_length = 108,
            .rc_expected = -ERR_PP1_CRLF,
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_SRC_PORT (+ prefix)",
            .raw_bytes_in = (const uint8_t*) "PROXY TCP4 1.2.3.4 5.6.7.8 +80 443\r\n",
            .raw_bytes_in_length = 36,
            .rc_expected = -ERR_PP1_SRC_PORT,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "1.2.3.4",
                .dst_addr = "5.6.7.8",
            },
        },
        {
            .name = "v1 PROXY protocol header: -ERR_PP1_DST_PORT (trailing garbage)",
            .raw_bytes_in = (const uint8_t*) "PROXY TCP4 1.2.3.4 5.6.7.8 80 443a\r\n",
            .raw_bytes_in_length = 36,
            .rc_expected = -ERR_PP1_DST_PORT,
            .pp_info_out_expected = {
                .address_family = ADDR_FAMILY_INET,
                .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
                .src_addr = "1.2.3.4",
                .dst_addr = "5.6.7.8",
                .src_port = 80,
            },
        },
    };

    /* Run tests */
    uint32_t i;
    for (i = 0; i < NUM_ELEMS(tests); i++)
    {
        pp_info_t pp_info_out = { 0 };
        int32_t pp_parse_hdr_rc = 0;
        printf("Running test: %s...", tests[i].name);
        if (tests[i].raw_bytes_in)
        {
            uint8_t *buffer = malloc(tests[i].raw_bytes_in_length);
            if (!buffer)
            {
                printf("FAILED\n");
                pp_info_clear(&pp_info_out);
                return EXIT_FAILURE;
            }
            memcpy(buffer, tests[i].raw_bytes_in, tests[i].raw_bytes_in_length);
            pp_parse_hdr_rc = pp_parse_hdr(buffer, tests[i].raw_bytes_in_length, &pp_info_out);
            free(buffer);
        }
        else
        {
            uint16_t pp_hdr_len = 0;
            uint16_t alignment = 1 << tests[i].pp_info_in.pp2_info.alignment_power;
            int32_t error = ERR_NULL;
            uint8_t *pp_hdr = NULL;

            if (tests[i].add_tlvs[0].type)
            {
                memcpy(tests[i].expected_tlvs, tests[i].add_tlvs, sizeof(tests[i].expected_tlvs));
                if (!pp_add_tlvs(&tests[i].pp_info_in, &tests[i].add_tlvs))
                {
                    printf("FAILED\n");
                    pp_info_clear(&pp_info_out);
                    return EXIT_FAILURE;
                }
            }

            if (tests[i].create_healthcheck)
            {
                pp_hdr = pp2_create_healthcheck_hdr(&pp_hdr_len, &error);
            }
            else
            {
                pp_hdr = pp_create_hdr(tests[i].version, &tests[i].pp_info_in, &pp_hdr_len, &error);
                pp_info_clear(&tests[i].pp_info_in);
            }
            if (tests[i].error_expected == ERR_NULL)
            {
                if (!pp_hdr
                    || error != ERR_NULL
                    || (alignment > 1 && pp_hdr_len % alignment))
                {
                    printf("FAILED\n");
                    pp_info_clear(&pp_info_out);
                    return EXIT_FAILURE;
                }
                tests[i].rc_expected = pp_hdr_len;
                pp_parse_hdr_rc = pp_parse_hdr(pp_hdr, pp_hdr_len, &pp_info_out);
            }
            else
            {
                if (pp_hdr || error != tests[i].error_expected)
                {
                    printf("FAILED\n");
                    pp_info_clear(&pp_info_out);
                    return EXIT_FAILURE;
                }
            }
            free(pp_hdr);
        }

        if (pp_parse_hdr_rc != tests[i].rc_expected
            || (pp_parse_hdr_rc && (!pp_info_equal(&pp_info_out, &tests[i].pp_info_out_expected) || !pp_verify_tlvs(&pp_info_out, &tests[i].expected_tlvs))))
        {
            printf("FAILED\n");
            pp_info_clear(&pp_info_out);
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info_out);
        printf("PASSED\n");
    }

    /* Test pp_info_add_* validation failures */
    printf("Running test: pp_info_add_unique_id length > 128...");
    {
        pp_info_t pp_info = { 0 };
        uint8_t dummy = 0;
        if (pp_info_add_unique_id(&pp_info, 129, &dummy) != 0)
        {
            printf("FAILED\n");
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info);
    }
    printf("PASSED\n");

    printf("Running test: pp_info_add_netns NULL...");
    {
        pp_info_t pp_info = { 0 };
        if (pp_info_add_netns(&pp_info, NULL) != 0)
        {
            printf("FAILED\n");
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info);
    }
    printf("PASSED\n");

    printf("Running test: pp_info_add_aws_vpce_id NULL...");
    {
        pp_info_t pp_info = { 0 };
        if (pp_info_add_aws_vpce_id(&pp_info, NULL) != 0)
        {
            printf("FAILED\n");
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info);
    }
    printf("PASSED\n");

    /* Test pp_strerror() */
    printf("Running test: pp_strerror()...");
    if (strcmp("No error", pp_strerror(ERR_NULL))
     || strcmp("v1 PROXY protocol header: invalid dst port", pp_strerror(-ERR_PP1_DST_PORT))
     || pp_strerror(-29) || pp_strerror(1))
    {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("PASSED\n");

    printf("All tests completed successfully\n");
    return EXIT_SUCCESS;
}
