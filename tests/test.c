#include <string.h>
#include "../src/proxy_protocol.h"

int main(int argc, char **argv)
{
    pp_info_t pp_info_in = {
        .dst_ip_str = "172.22.32.1",
        .dst_port = 443,
        .src_ip_str = "192.168.1.1",
        .src_port = 8080
    };
    pp_info_t pp_info_out = {};
    uint32_t pp_msg_v2_len;
    uint8_t *pp_msg_v2 = ppv2_create_message(AF_INET, &pp_info_in, &pp_msg_v2_len);
    pp_parse(pp_msg_v2, pp_msg_v2_len, &pp_info_out);
    if (memcmp(&pp_info_in, &pp_info_out, sizeof(pp_info_out)))
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}