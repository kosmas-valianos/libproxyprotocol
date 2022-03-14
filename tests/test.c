#include <stdio.h>
#include <string.h>
#include "../src/proxy_protocol.h"

#define NUM_ELEMS(array) (uint32_t)(sizeof(array) / sizeof(array[0]))

typedef struct
{
    const char *name;
    uint8_t     version;
    uint8_t     fam;
    pp_info_t   pp_info_in;
    uint8_t    *raw_bytes_in;
    uint32_t    raw_bytes_in_length;
    int         rc_expected;
    pp_info_t   pp_info_out_expected;
} test_t;

uint8_t vpce_msg[] = {
            0x0d, 0x0a, 0x0d, 0x0a, /* Start of Sig */
            0x00, 0x0d, 0x0a, 0x51,
            0x55, 0x49, 0x54, 0x0a, /* End of Sig */
            0x21, 0x11, 0x00, 0x54, /* ver_cmd, fam and len */
            0xac, 0x1f, 0x07, 0x71, /* Caller src ip */
            0xac, 0x1f, 0x0a, 0x1f, /* Endpoint dst ip */
            0xc8, 0xf2, 0x00, 0x50, /* Proxy src port & dst port */
            0x03, 0x00, 0x04, 0xe8, /* CRC TLV start */
            0xd6, 0x89, 0x2d, 0xea, /* CRC TLV cont, VPCE id TLV start */
            0x00, 0x17, 0x01, 0x76,
            0x70, 0x63, 0x65, 0x2d,
            0x30, 0x38, 0x64, 0x32,
            0x62, 0x66, 0x31, 0x35,
            0x66, 0x61, 0x63, 0x35,
            0x30, 0x30, 0x31, 0x63,
            0x39, 0x04, 0x00, 0x24, /* VPCE id TLV end, NOOP TLV start*/
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, /* NOOP TLV end */
};

static uint8_t pp_info_equal(const pp_info_t *pp_info_a, const pp_info_t *pp_info_b)
{
    if (pp_info_a->local != pp_info_b->local)
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
    return 1;
}

int main(int argc, char **argv)
{
    // Define tests
    test_t tests[] = {
        {
            .name = "v1 PROXY message: UNKNOWN - short",
            .raw_bytes_in = "PROXY UNKNOWN\r\n",
            .raw_bytes_in_length = strlen(tests[0].raw_bytes_in),
            .rc_expected = strlen(tests[0].raw_bytes_in),
        },
        {
            .name = "v1 PROXY message: UNKNOWN - full",
            .raw_bytes_in = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            .raw_bytes_in_length = strlen(tests[1].raw_bytes_in),
            .rc_expected = strlen(tests[1].raw_bytes_in),
        },
        {
            .name = "v2 PROXY message: PROXY, AF_INET, PP2_TYPE_CRC32C, PP2_SUBTYPE_AWS_VPCE_ID",
            .raw_bytes_in = vpce_msg,
            .raw_bytes_in_length = sizeof(vpce_msg),
            .rc_expected = sizeof(vpce_msg),
            .pp_info_out_expected = {
                .src_addr = "172.31.7.113",
                .dst_addr = "172.31.10.31",
                .src_port = 51442,
                .dst_port = 80
            },
        },
        {
            .name = "v2 PROXY message: PROXY, AF_INET create and parse",
            .version = 2,
            .fam = AF_INET,
            .pp_info_in = {
                .src_addr = "172.31.7.113",
                .dst_addr = "172.31.10.31",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[3].pp_info_in,
        },
        {
            .name = "v1 PROXY message: AF_INET create and parse",
            .version = 1,
            .fam = AF_INET,
            .pp_info_in = {
                .src_addr = "172.31.7.113",
                .dst_addr = "172.31.10.31",
                .src_port = 51442,
                .dst_port = 80
            },
            .pp_info_out_expected = tests[4].pp_info_in,
        },
        {
            .name = "v2 PROXY message: PROXY, AF_UNIX create and parse",
            .version = 2,
            .fam = AF_UNIX,
            .pp_info_in = {
                .src_addr = "/tmp/testsocket1.socket",
                .dst_addr = "/tmp/testsocket2.socket",
            },
            .pp_info_out_expected = tests[5].pp_info_in,
        },
        {
            .name = "v2 PROXY message: LOCAL, AF_UNSPEC create and parse",
            .version = 2,
            .fam = '\x00',
            .pp_info_in = { .local = 1 },
            .pp_info_out_expected = { .local = 1 },
        },
    };

    // Run tests
    uint32_t i;
    for (i = 0; i < NUM_ELEMS(tests); i++)
    {
        printf("Running test: %s...", tests[i].name);
        pp_info_t pp_info_out;
        int rc;
        if (tests[i].raw_bytes_in)
        {
            rc = pp_parse(tests[i].raw_bytes_in, tests[i].raw_bytes_in_length, &pp_info_out);
            //uint16_t tlv_value_len;
            //uint8_t *tlv_value = pp_info_get_tlv_value(&ppv1_info_out, PP2_TYPE_AWS, PP2_SUBTYPE_AWS_VPCE_ID, &tlv_value_len);
        }
        else
        {
            uint32_t pp_msg_len;
            int error;
            uint8_t *pp_msg = pp_create_msg(tests[i].version, tests[i].fam, &tests[i].pp_info_in, &pp_msg_len, &error);
            tests[i].rc_expected = pp_msg_len;
            rc = pp_parse(pp_msg, pp_msg_len, &pp_info_out);
            free(pp_msg);
        }

        if (rc != tests[i].rc_expected || !pp_info_equal(&pp_info_out, &tests[i].pp_info_out_expected))
        {
            printf("FAILED\n");
            pp_info_clear(&pp_info_out);
            return EXIT_FAILURE;
        }
        pp_info_clear(&pp_info_out);
        printf("PASSED\n");
    }
    printf("ALl tests completed successfully\n");
    getchar();
    return EXIT_SUCCESS;
}
