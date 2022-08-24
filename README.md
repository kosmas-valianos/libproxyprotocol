# libproxyprotocol
An ANSI C library to **parse** and **create** [PROXY protocol](https://www.haproxy.org/download/2.7/doc/proxy-protocol.txt) v1 and v2 headers with support for **all TLVs** including the custom ones from AWS and Azure
* Full coverage of the latest 2.6 specification.
* Easy addition of any TLV through API functions when creating v2 PROXY protocol headers.
* Easy access of the values of the extracted v2 TLVs though API functions. Moreover, in case the v2 TLV values are US-ASCII string names, they are given as proper NULL terminated strings for easy usage.
* Easy way through the API to request a specific alignment, CRC32C checksum when creating v2 PROXY protocol headers.
* Easy way through an API function to create health check v2 PROXY protocol headers.
* Socket free logic. Does not hook, manipulate, assume any networking. It merely works on buffers.
* Compilable with most compilers and usable at any platform as it is written in ANSI C.

## Installation
The library should be compilable to any platform as it is written in ANSI C. It comes with a Makefile which can create the shared library `libproxyprotocol.so` which can then be linked to your application. You can of course link statically as well using the .o directly. Special care has been taken to make it work with Windows as well. In that case you have to compile it to a .dll/.lib yourself. In case of Windows remember that you have to link with the `ws2_32.lib`. An example of this is shown in tests.

## API/Usage
All the API details are in the proxy_protocol.h. The complete example for creating/parsing v1 and v2 PROXY protocol headers can be found at `examples/client_server.c`

### Create a v1 PROXY protocol header
```
pp_info_t pp_info_in_v1 = {
        .address_family = ADDR_FAMILY_INET,
        .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
        .src_addr = "172.22.32.1",
        .dst_addr = "172.22.33.1",
        .src_port = 4040,
        .dst_port = 443
    };
uint16_t pp1_hdr_len;
int32_t error;
uint8_t *pp1_hdr = pp_create_hdr(1, &pp_info_in_v1, &pp1_hdr_len, &error);
/* Clear the pp_info passed in pp_create_hdr(). Not really needed for v1 but good to do out of principle */
pp_info_clear(&pp_info_in_v1);
if (error != ERR_NULL)
{
    fprintf(stderr, "pp_create_hdr() failed: %s", pp_strerror(error));
    return EXIT_FAILURE;
}
```

### Parse a v1 PROXY protocol header
```
pp_info_t pp_info_out;
int32_t rc = pp_parse_hdr(pp1_hdr, pp1_hdr_len, &pp_info_out);
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
```
```
45 bytes PROXY protocol header: 172.22.32.1 172.22.33.1 4040 443
```

### Create a v2 PROXY protocol header
```
pp_info_t pp_info_in_v2 = {
    .address_family = ADDR_FAMILY_INET,
    .transport_protocol = TRANSPORT_PROTOCOL_STREAM,
    .src_addr = "192.168.10.100",
    .dst_addr = "192.168.11.90",
    .src_port = 42332,
    .dst_port = 8080,
    .pp2_info = {
        .crc32c = 1,        /* Add crc32c checksum */
        .pp2_ssl_info = {   /* Add SSL information */
            .ssl = 1,
            .cert_in_connection = 1,
            .cert_in_session = 1,
            .cert_verified = 1,
        }
    }
};
/* Add SSL TLVs */
/* IMPORTANT: Always clear the pp_info to be passed in pp_create_hdr() because TLVs are allocated in heap. Otherwise memory will be leaked */
if (!pp_info_add_ssl(&pp_info_in_v2, "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "SHA256", "RSA2048", "example.com", 11))
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
uint8_t *pp2_hdr = pp_create_hdr(2, &pp_info_in_v2, &pp1_hdr_len, &error);
pp_info_clear(&pp_info_in_v2);
if (error != ERR_NULL)
{
    fprintf(stderr, "pp_create_hdr() failed: %s", pp_strerror(error));
    return EXIT_FAILURE;
}
```

### Parse a v2 PROXY protocol header
```
rc = pp_parse_hdr(pp2_hdr, pp1_hdr_len, &pp_info_out);
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
    uint16_t length, cn_length;
    const uint8_t *azure_linkid = pp_info_get_azure_linkid(&pp_info_out, &length);
    uint32_t linkid;
    memcpy(&linkid, azure_linkid, length);
    const uint8_t *cn = pp_info_get_ssl_cn(&pp_info_out, &cn_length);
    printf("%d bytes PROXY protocol header:\n"
            "\tAzure Link ID: %u\n"
            "\tCRC32C checksum: %s\n"
            "\tSSL version: %s\n"
            "\tSSL cipher: %s\n"
            "\tSSL sig_alg: %s\n"
            "\tSSL key_alg: %s\n"
            "\tSSL CN: %.*s\n"
            "%s %s %hu %hu\n",
        rc, linkid,
        pp_info_out.pp2_info.crc32c == 1 ? "verified" : "not present",
        pp_info_get_ssl_version(&pp_info_out, &length),
        pp_info_get_ssl_cipher(&pp_info_out, &length),
        pp_info_get_ssl_sig_alg(&pp_info_out, &length),
        pp_info_get_ssl_key_alg(&pp_info_out, &length),
        cn_length, cn,
        pp_info_out.src_addr, pp_info_out.dst_addr,
        pp_info_out.src_port, pp_info_out.dst_port);
}
/* ALWAYS clear the pp_info after a call to pp_parse_hdr() */
pp_info_clear(&pp_info_out);
```
```
124 bytes PROXY protocol header:
   Azure Link ID: 1234
   CRC32C checksum: verified
   SSL version: TLSv1.2
   SSL cipher: ECDHE-RSA-AES128-GCM-SHA256
   SSL sig_alg: SHA256
   SSL key_alg: RSA2048
   SSL CN: example.com
   192.168.10.100 192.168.11.90 42332 8080
```
