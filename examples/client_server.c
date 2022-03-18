#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>
#endif

#include "../src/proxy_protocol.h"

int main()
{
    // Create a v1 PROXY protocol header
    pp_info_t pp_info_in = {
        .src_addr = "172.22.32.1",
        .dst_addr = "172.22.33.1",
        .src_port = 4040,
        .dst_port = 443
    };
    uint32_t pp1_hdr_len;
    uint32_t error;
    uint8_t *pp1_hdr = pp_create_hdr(1, AF_INET, &pp_info_in, &pp1_hdr_len, &error);
    if (!pp1_hdr)
    {
        fprintf(stderr, "pp_create_hdr() failed: %s", pp_strerror(error));
        free(pp1_hdr);
        return EXIT_FAILURE;
    }

    // Parse
    pp_info_t pp_info_out;
    int32_t rc = pp_parse_hdr(pp1_hdr, pp1_hdr_len, &pp_info_out);
    free(pp1_hdr);
    if (rc == 0)
    {
        printf("Not a PROXY protocol header\n");
    }
    else if (rc < 0)
    {
        fprintf(stderr, "pp_parse_hdr() failed: %s", pp_strerror(rc));
        pp_info_clear(&pp_info_out);
        return EXIT_FAILURE;
    }
    else
    {
        printf("%d bytes PROXY protocol header: %s %s %hu %hu\n",
            rc,
            pp_info_out.src_addr, pp_info_out.dst_addr,
            pp_info_out.src_port, pp_info_out.dst_port);
    }
    pp_info_clear(&pp_info_out);

    // Parse
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

    rc = pp_parse_hdr(pp2_hdr_vpce, sizeof(pp2_hdr_vpce), &pp_info_out);
    if (rc == 0)
    {
        printf("Not a PROXY protocol header\n");
    }
    else if (rc < 0)
    {
        fprintf(stderr, "pp_parse_hdr() failed: %s", pp_strerror(rc));
        pp_info_clear(&pp_info_out);
        return EXIT_FAILURE;
    }
    else
    {
        uint16_t tlv_value_len;
        char *vpc_id = pp_info_get_tlv_value(&pp_info_out, PP2_TYPE_AWS, PP2_SUBTYPE_AWS_VPCE_ID, &tlv_value_len);
        printf("%d bytes PROXY protocol header:  AWS VPC ID: %s. %s %s %hu %hu\n",
            rc, vpc_id,
            pp_info_out.src_addr, pp_info_out.dst_addr,
            pp_info_out.src_port, pp_info_out.dst_port);
    }
    pp_info_clear(&pp_info_out);

    return EXIT_SUCCESS;
}