#include <stdio.h>
#include <string.h>
#include "../src/proxy_protocol.h"

typedef struct
{
    const char *name;
    int         error_expected;
    pp_info_t   pp_info_in;
    pp_info_t   pp_info_out_expected;
} test_t;

int main(int argc, char **argv)
{
    int error, rc;
    pp_info_t pp_info_in = {
        .dst_ip_str = "172.22.32.1",
        .dst_port = 443,
        .src_ip_str = "192.168.1.1",
        .src_port = 8080
    };
    pp_info_t ppv2_info_out = { 0 };
    pp_info_t ppv1_info_out = { 0 };
    uint32_t pp_msg_v2_len, pp_msg_v1_len;
    uint8_t *pp_msg_v2 = ppv2_create_message(AF_INET, &pp_info_in, &pp_msg_v2_len, &error);
    uint8_t *pp_msg_v1 = ppv1_create_message(AF_INET, &pp_info_in, &pp_msg_v1_len, &error);
    fprintf(stderr, "error is %d\n", error);

    rc = pp_parse(pp_msg_v2, pp_msg_v2_len, &ppv2_info_out);
    fprintf(stderr, "rc is %d\n", rc);
    rc = pp_parse(pp_msg_v1, pp_msg_v1_len, &ppv1_info_out);
    fprintf(stderr, "rc is %d\n", rc);
    const char *v1_unknown = "PROXY UNKNOWN\r\n";
    const char* v1_unknown1 = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
    rc = pp_parse(v1_unknown, strlen(v1_unknown), &ppv1_info_out);
    fprintf(stderr, "rc unknown is %d. strlen is %d\n", rc, strlen(v1_unknown));
    rc = pp_parse(v1_unknown1, strlen(v1_unknown1), &ppv1_info_out);
    fprintf(stderr, "rc unknown1 is %d. strlen is %d\n", rc, strlen(v1_unknown1));
    if (memcmp(&pp_info_in, &ppv2_info_out, sizeof(ppv2_info_out)))
    {
        getchar();
        return EXIT_FAILURE;
    }
    if (memcmp(&pp_info_in, &ppv1_info_out, sizeof(ppv1_info_out)))
    {
        getchar();
        return EXIT_FAILURE;
    }
    getchar();
    return EXIT_SUCCESS;
}