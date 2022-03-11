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
    pp_info_t ppv2_info_out = { 0 };
    pp_info_t ppv1_info_out = {0};
    uint32_t pp_msg_v2_len, pp_msg_v1_len;
    uint8_t *pp_msg_v2 = ppv2_create_message(AF_INET, &pp_info_in, &pp_msg_v2_len);
    uint8_t *pp_msg_v1 = ppv1_create_message(AF_INET, &pp_info_in, &pp_msg_v1_len);

    pp_parse(pp_msg_v2, pp_msg_v2_len, &ppv2_info_out);
    pp_parse(pp_msg_v1, pp_msg_v1_len, &ppv1_info_out);
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