#include <stdio.h>
#include <string.h>
#include "../src/proxy_protocol.h"

typedef struct
{
    const char    *name;
    pp_info_t      pp_info_in;
    uint8_t       *raw_bytes_in;
    uint32_t       raw_bytes_in_length;
    int            rc_expected;
    pp_info_t      pp_info_out_expected;
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
            .name = "v2 PROXY message: PP2_TYPE_CRC32C, PP2_SUBTYPE_AWS_VPCE_ID",
            .raw_bytes_in = vpce_msg,
            .raw_bytes_in_length = sizeof(vpce_msg),
            .rc_expected = sizeof(vpce_msg),
            .pp_info_out_expected = {
                .src_ip_str = "172.31.7.113",
                .src_port = 51442,
                .dst_ip_str = "172.31.10.31",
                .dst_port = 80
            },
        },
    };

    // Run tests
    uint32_t i;
    for (i = 0; i < 3; i++)
    {
        printf("Running test: %s...", tests[i].name);
        if (tests[i].raw_bytes_in)
        {
            pp_info_t ppv1_info_out;
            int rc = pp_parse(tests[i].raw_bytes_in, tests[i].raw_bytes_in_length, &ppv1_info_out);
            uint16_t tlv_value_len;
            uint8_t *tlv_value = pp_info_get_tlv_value(&ppv1_info_out, PP2_TYPE_AWS, PP2_SUBTYPE_AWS_VPCE_ID, &tlv_value_len);
            if (rc != tests[i].rc_expected || memcmp(&ppv1_info_out, &tests[i].pp_info_out_expected, sizeof(pp_info_t)- sizeof(tlv_array_t)))
            {
                printf("FAILED\n");
                pp_info_clear(&ppv1_info_out);
                return EXIT_FAILURE;
            }
            pp_info_clear(&ppv1_info_out);
            printf("PASSED\n");
        }
    }
    printf("ALl tests completed successfully\n");
    getchar();
    return EXIT_SUCCESS;
}
