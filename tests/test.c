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
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
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
    uint8_t *value;
} test_tlv_t;

typedef struct
{
    const char *name;
    uint8_t     version;
    pp_info_t   pp_info_in;
    uint8_t    *raw_bytes_in;
    uint32_t    raw_bytes_in_length;
    int32_t     rc_expected;
    pp_info_t   pp_info_out_expected;
    test_tlv_t  expected_tlvs[10];
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

static uint8_t pp_verify_tlvs(const pp_info_t *pp_info, const test_tlv_t (*expected_tlvs)[10])
{
    uint8_t i;
    for (i = 0; i < 10; i++)
    {
        const test_tlv_t *test_tlv = &(*expected_tlvs)[i];
        if (test_tlv->type != 0)
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
            case PP2_TYPE_NETNS:
                tlv_value = pp_info_get_ssl_netns(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_AWS:
                tlv_value = pp_info_get_aws_vpce_id(pp_info, &tlv_value_len);
                break;
            case PP2_TYPE_AZURE:
                tlv_value = pp_info_get_azure_linkid(pp_info, &tlv_value_len);
                break;
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
    if (memcmp(&pp_info_a->pp2_info, &pp_info_b->pp2_info, sizeof(pp2_info_t)))
    {
        return 0;
    }
    return 1;
}

int main()
{
    /* Define tests */
    test_t tests[] = {
        {
            .name = "v1 PROXY protocol header: UNKNOWN - short",
            .raw_bytes_in = (uint8_t *) "PROXY UNKNOWN\r\n",
            .raw_bytes_in_length = strlen((char*)tests[0].raw_bytes_in),
            .rc_expected = strlen((char*)tests[0].raw_bytes_in),
        },
        {
            .name = "v1 PROXY protocol header: UNKNOWN - full",
            .raw_bytes_in = (uint8_t *) "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            .raw_bytes_in_length = strlen((char *) tests[1].raw_bytes_in),
            .rc_expected = strlen((char *) tests[1].raw_bytes_in),
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
                .dst_port = 8080
            },
            .expected_tlvs = {
                {
                    .type = PP2_TYPE_CRC32C,
                    .value_len = 4,
                    .value = (uint8_t *) "\xe5\x18\x86\xf8"
                },
                {
                    .type = PP2_TYPE_AWS,
                    .subtype = PP2_SUBTYPE_AWS_VPCE_ID,
                    .value_len = 23,
                    .value = (uint8_t *) "vpce-23d8ezjk38bchilm4"
                },
            },
        },
        {
            .name = "v2 PROXY protocol header: PROXY, TCP over IPv4 create and parse",
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
            .name = "v1 PROXY protocol header: TCP4 create and parse",
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
            .name = "v2 PROXY protocol header: PROXY, UNIX stream create and parse",
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
            .name = "v2 PROXY protocol header: LOCAL, AF_UNSPEC create and parse",
            .version = 2,
            .pp_info_in = {
                .address_family = ADDR_FAMILY_UNSPEC,
                .transport_protocol = TRANSPORT_PROTOCOL_UNSPEC,
                .pp2_info.local = 1
            },
            .pp_info_out_expected = tests[6].pp_info_in,
        },
        {
            .name = "v2 PROXY protocol header: PROXY, TCP over IPv6 create and parse",
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
            .name = "v1 PROXY protocol header: TCP6 create and parse",
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
            .name = "v2 PROXY protocol header: PROXY, TCP over IPv4. TLVs: "
                    "PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN, PP2_SUBTYPE_SSL_CIPHER, PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG ",
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
                .pp2_info = { .local = 0, .pp2_ssl_info = {
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
                    .value = (uint8_t*)"TLSv1.2"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CN,
                    .value_len = 11,
                    /* example.com */
                    .value = (uint8_t*)"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d"
                },
                {
                    .type = PP2_SUBTYPE_SSL_CIPHER,
                    .value_len = 28,
                    .value = (uint8_t*)"ECDHE-RSA-AES128-GCM-SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_SIG_ALG,
                    .value_len = 7,
                    .value = (uint8_t*)"SHA256"
                },
                {
                    .type = PP2_SUBTYPE_SSL_KEY_ALG,
                    .value_len = 8,
                    .value = (uint8_t*)"RSA2048"
                },
            },
        },
    };

    /* Run tests */
    uint32_t i;
    for (i = 0; i < NUM_ELEMS(tests); i++)
    {
        printf("Running test: %s...", tests[i].name);
        pp_info_t pp_info_out;
        int32_t rc;
        if (tests[i].raw_bytes_in)
        {
            rc = pp_parse_hdr(tests[i].raw_bytes_in, tests[i].raw_bytes_in_length, &pp_info_out);
        }
        else
        {
            uint16_t pp_hdr_len;
            uint32_t error;
            uint8_t *pp_hdr = pp_create_hdr(tests[i].version, &tests[i].pp_info_in, &pp_hdr_len, &error);
            if (!pp_hdr || error != ERR_NULL)
            {
                printf("FAILED\n");
                pp_info_clear(&pp_info_out);
                return EXIT_FAILURE;
            }
            tests[i].rc_expected = pp_hdr_len;
            rc = pp_parse_hdr(pp_hdr, pp_hdr_len, &pp_info_out);
            free(pp_hdr);
        }

        if (rc != tests[i].rc_expected || !pp_info_equal(&pp_info_out, &tests[i].pp_info_out_expected) || !pp_verify_tlvs(&pp_info_out, &tests[i].expected_tlvs))
        {
            printf("FAILED\n");
            pp_info_clear(&pp_info_out);
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info_out);
        printf("PASSED\n");
    }

    /* Test pp_strerror() */
    printf("Running test: pp_strerror()...");
    if (strcmp("No error", pp_strerror(ERR_NULL))
     || strcmp("v1 PROXY protocol header: invalid dst port", pp_strerror(ERR_PP1_DST_PORT))
     || pp_strerror(-29) || pp_strerror(1))
    {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("PASSED\n");

    printf("ALl tests completed successfully\n");
    return EXIT_SUCCESS;
}
