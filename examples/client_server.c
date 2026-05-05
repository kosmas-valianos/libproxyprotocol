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

/* Self-signed EC (prime256v1) X.509 DER certificate, CN=test */
static const uint8_t client_cert_der[] = {
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

int main(void)
{
    int32_t error = ERR_NULL;
    int32_t rc;

    pp_info_t pp_info_in_v1 = {
        ADDR_FAMILY_INET,
        TRANSPORT_PROTOCOL_STREAM,
        "172.22.32.1",
        "172.22.33.1",
        4040,
        443,
        { 0 }
    };
    uint8_t *pp1_hdr = NULL;
    uint16_t pp1_hdr_len = 0;

    pp_info_t pp_info_in_v2 = {
        ADDR_FAMILY_INET,
        TRANSPORT_PROTOCOL_STREAM,
        "192.168.10.100",
        "192.168.11.90",
        42332,
        8080,
        { 0 }
    };
    uint8_t *pp2_hdr = NULL;
    uint16_t pp2_hdr_len = 0;

    pp_info_t pp_info_out = { 0 };

    /* Create a v1 PROXY protocol header */
    pp1_hdr = pp_create_hdr(1, &pp_info_in_v1, &pp1_hdr_len, &error);
    /* Clear the pp_info passed in pp_create_hdr(). Not really needed for v1 but good to do out of principle */
    pp_info_clear(&pp_info_in_v1);
    if (error != ERR_NULL)
    {
        fprintf(stderr, "pp_create_hdr() failed: %s", pp_strerror(error));
        return EXIT_FAILURE;
    }

    /* Parse a v1 PROXY protocol header */
    rc = pp_parse_hdr(pp1_hdr, pp1_hdr_len, &pp_info_out);
    free(pp1_hdr);
    if (!rc)
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
    /* ALWAYS clear the pp_info after a call to pp_parse_hdr() */
    pp_info_clear(&pp_info_out);

    /* Create a v2 PROXY protocol header with some TLVs */
    /* Add crc32c checksum */
    pp_info_in_v2.pp2_info.crc32c = 1;
    /* Add SSL information */
    pp_info_in_v2.pp2_info.pp2_ssl_info.ssl = 1;
    pp_info_in_v2.pp2_info.pp2_ssl_info.cert_in_connection = 1;
    pp_info_in_v2.pp2_info.pp2_ssl_info.cert_in_session = 1;
    pp_info_in_v2.pp2_info.pp2_ssl_info.cert_verified = 1;
    /* Add SSL TLVs */
    /* IMPORTANT: Always clear the pp_info to be passed in pp_create_hdr() because TLVs are allocated in heap. Otherwise memory will be leaked */
    if (!pp_info_add_ssl(&pp_info_in_v2, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "SHA256", "RSA2048", "secp256r1", "rsa_pss_rsae_sha256", (const uint8_t*) "example.com", 11, client_cert_der, sizeof(client_cert_der)))
    {
        fprintf(stderr, "pp_info_add_ssl() failed\n");
        pp_info_clear(&pp_info_in_v2);
        return EXIT_FAILURE;
    }
    /* Add Azure Link ID TLV */
    if (!pp_info_add_azure_linkid(&pp_info_in_v2, 1234))
    {
        fprintf(stderr, "pp_info_add_azure_linkid() failed\n");
        pp_info_clear(&pp_info_in_v2);
        return EXIT_FAILURE;
    }
    pp2_hdr = pp_create_hdr(2, &pp_info_in_v2, &pp2_hdr_len, &error);
    pp_info_clear(&pp_info_in_v2);
    if (error != ERR_NULL)
    {
        fprintf(stderr, "pp_create_hdr() failed: %s", pp_strerror(error));
        return EXIT_FAILURE;
    }

    /* Parse a v2 PROXY protocol header */
    rc = pp_parse_hdr(pp2_hdr, pp2_hdr_len, &pp_info_out);
    free(pp2_hdr);
    if (!rc)
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
        uint16_t length, cn_length, client_cert_length;
        uint32_t linkid;
        const uint8_t *azure_linkid = pp_info_get_azure_linkid(&pp_info_out, &length);
        const uint8_t *cn = pp_info_get_ssl_cn(&pp_info_out, &cn_length);
        const uint8_t *client_cert = pp_info_get_ssl_client_cert(&pp_info_out, &client_cert_length);
        memcpy(&linkid, azure_linkid, length);
        printf("%d bytes PROXY protocol header:\n"
               "\tAzure Link ID: %u\n"
               "\tCRC32C checksum: %s\n"
               "\tSSL version: %s\n"
               "\tSSL cipher: %s\n"
               "\tSSL sig_alg: %s\n"
               "\tSSL key_alg: %s\n"
               "\tSSL group: %s\n"
               "\tSSL sig_scheme: %s\n"
               "\tSSL CN: %.*s\n"
               "\tSSL client_cert: %s\n"
               "\t%s %s %hu %hu\n",
            rc, linkid,
            /* In case CRC32c is wrong then rc < 0 => pp_strerror(rc) at previous block will print the error */
            pp_info_out.pp2_info.crc32c == 1 ? "verified" : "not present",
            pp_info_get_ssl_version(&pp_info_out, &length),
            pp_info_get_ssl_cipher(&pp_info_out, &length),
            pp_info_get_ssl_sig_alg(&pp_info_out, &length),
            pp_info_get_ssl_key_alg(&pp_info_out, &length),
            pp_info_get_ssl_group(&pp_info_out, &length),
            pp_info_get_ssl_sig_scheme(&pp_info_out, &length),
            cn_length, cn,
            client_cert ? "present" : "not present",
            pp_info_out.src_addr, pp_info_out.dst_addr,
            pp_info_out.src_port, pp_info_out.dst_port);
    }
    /* ALWAYS clear the pp_info after a call to pp_parse_hdr() */
    pp_info_clear(&pp_info_out);

    return EXIT_SUCCESS;
}
