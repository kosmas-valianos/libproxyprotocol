#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#pragma pack(1)

/******************* PROXY Protocol Version 1 *******************/
/*
 * The maximum line lengths the receiver must support including the CRLF are :
  - TCP/IPv4 :
      "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"
    => 5 + 1 + 4 + 1 + 15 + 1 + 15 + 1 + 5 + 1 + 5 + 2 = 56 chars

  - TCP/IPv6 :
      "PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
    => 5 + 1 + 4 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 104 chars

  - unknown connection (short form) :
      "PROXY UNKNOWN\r\n"
    => 5 + 1 + 7 + 2 = 15 chars

  - worst case (optional fields set to 0xff) :
      "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
    => 5 + 1 + 7 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 107 chars

So a 108-byte buffer is always enough to store all the line and a trailing zero
for string processing.
 */

static const char *crlf = "\r\n";

typedef struct
{
    char block[108];
} proxy_hdr_v1_t;

/****************************************************************/

/******************* PROXY Protocol Version 2 *******************/

typedef struct
{
    uint8_t  sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t  ver_cmd;  /* protocol version and command */
    uint8_t  fam;      /* protocol family and address */
    uint16_t len;      /* number of following bytes part of the header */
} proxy_hdr_v2_t;

typedef union
{
    struct
    {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ipv4_addr;
    struct
    {        /* for TCP/UDP over IPv6, len = 36 */
        uint8_t  src_addr[16];
        uint8_t  dst_addr[16];
        uint16_t src_port;
        uint16_t dst_port;
    } ipv6_addr;
    struct
    {        /* for AF_UNIX sockets, len = 216 */
        uint8_t src_addr[108];
        uint8_t dst_addr[108];
    } unix_addr;
} proxy_addr_t;

/* Type-Length-Value (TLV vectors) */
#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30
/* Custom TLVs */
#define PP2_TYPE_AWS            0xEA

typedef struct
{
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[1];
} pp2_tlv_t;

/* PP2_TYPE_SSL type and subtypes */
#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

typedef struct
{
    uint8_t   client;
    uint32_t  verify;
    pp2_tlv_t sub_tlv[1];
} pp2_tlv_ssl_t;

/* PP2_TYPE_AWS type and subtypes */
#define PP2_SUBTYPE_AWS_VPCE_ID 0x01

typedef struct
{
    uint8_t type;
    uint8_t value[1];
} pp2_tlv_aws_t;

/****************************************************************/

#pragma pack()

typedef char ip_str_t[INET6_ADDRSTRLEN];

typedef struct
{
    ip_str_t  src_ip_str;
    uint16_t  src_port;
    ip_str_t  dst_ip_str;
    uint16_t  dst_port;
} pp_info_t;

static char *byte_array_to_hex_str(const uint8_t *byte_array, uint32_t byte_array_size, char **hex_str)
{
    static const char *hex_chars = "0123456789abcdef";
    *hex_str = malloc(2 * byte_array_size + 1);
    uint32_t i = 0;
    for (i = 0; i < byte_array_size; i++)
    {
        (*hex_str)[2*i    ] = hex_chars[(byte_array[i] >> 4) & 0xf];
        (*hex_str)[2*i + 1] = hex_chars[(byte_array[i]     ) & 0xf];
    }
    (*hex_str)[2 * byte_array_size] = '\0';
    return *hex_str;
}

static bool parse_port(const char *value, uint16_t *usport)
{
    uint64_t port = strtoul(value, NULL, 10);
    if (port == 0 || port > UINT16_MAX)
    {
        fprintf(stderr, "Illegal port %s", value);
        return false;
    }
    *usport = (uint16_t) port;
    return true;
}

uint8_t *ppv2_create_message(uint8_t fam, const pp_info_t *proxy_info)
{
    typedef struct
    {
        proxy_hdr_v2_t proxy_hdr_v2;
        proxy_addr_t   proxy_addr;
    } proxy_message_v2_t;

    uint16_t len = (fam == AF_INET) ? 12 : 36;
    proxy_message_v2_t msg = {
            .proxy_hdr_v2.sig = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",
            .proxy_hdr_v2.ver_cmd = '\x21',
            .proxy_hdr_v2.fam = (fam == AF_INET) ? '\x11' : '\x21',
            .proxy_hdr_v2.len = htons(len)
    };

    if (fam == AF_INET)
    {
        if (inet_pton(AF_INET, proxy_info->src_ip_str, &msg.proxy_addr.ipv4_addr.src_addr) != 1)
        {
            fprintf(stderr, "Invalid v2 PROXY message: invalid IPv4 src IP: %s", proxy_info->src_ip_str);
            return NULL;
        }
        if (inet_pton(AF_INET, proxy_info->dst_ip_str, &msg.proxy_addr.ipv4_addr.dst_addr) != 1)
        {
            fprintf(stderr, "Invalid v2 PROXY message: invalid IPv4 dst IP: %s", proxy_info->dst_ip_str);
            return NULL;
        }
        msg.proxy_addr.ipv4_addr.src_port = htons(proxy_info->src_port);
        msg.proxy_addr.ipv4_addr.dst_port = htons(proxy_info->dst_port);
    }
    else if (fam == AF_INET6)
    {
        if (inet_pton(AF_INET6, proxy_info->src_ip_str, &msg.proxy_addr.ipv6_addr.src_addr) != 1)
        {
            fprintf(stderr, "Invalid v2 PROXY message: invalid IPv4 src IP: %s", proxy_info->src_ip_str);
            return NULL;
        }
        if (inet_pton(AF_INET6, proxy_info->dst_ip_str, &msg.proxy_addr.ipv6_addr.dst_addr) != 1)
        {
            fprintf(stderr, "Invalid v2 PROXY message: invalid IPv6 dst IP: %s", proxy_info->dst_ip_str);
            return NULL;
        }
        msg.proxy_addr.ipv6_addr.src_port = htons(proxy_info->src_port);
        msg.proxy_addr.ipv6_addr.dst_port = htons(proxy_info->dst_port);
    }

    /* Serialize the msg */
    uint32_t pp_msg_v2_len = sizeof(proxy_hdr_v2_t) + len;
    uint8_t *pp_msg_v2 = malloc(pp_msg_v2_len);
    memcpy(pp_msg_v2, &msg.proxy_hdr_v2, sizeof(proxy_hdr_v2_t));
    memcpy(pp_msg_v2 + sizeof(proxy_hdr_v2_t), &msg.proxy_addr, len);

    char *hex_str_msg = NULL;
    fprintf(stderr, "Created v2 PROXY message %s", byte_array_to_hex_str(pp_msg_v2, pp_msg_v2_len, &hex_str_msg));
    free(hex_str_msg);

    return pp_msg_v2;
}

char *ppv1_create_message(uint8_t fam, const pp_info_t *proxy_info)
{
    char *inet_family = fam == AF_INET ? "TCP4" : "TCP6";
    uint32_t pp_msg_v1_len = sizeof(proxy_hdr_v1_t) + strlen(crlf);
    char *pp_msg_v1 = malloc(pp_msg_v1_len);
    sprintf(pp_msg_v1, "PROXY %s %s %s %hu %hu",
        inet_family, proxy_info->src_ip_str, proxy_info->dst_ip_str, proxy_info->src_port, proxy_info->dst_port);
    memcpy(pp_msg_v1 + sizeof(proxy_hdr_v1_t), crlf, strlen(crlf));
    char *hex_str_msg = NULL;
    fprintf(stderr, "Created v1 PROXY message \"%s\"", byte_array_to_hex_str((uint8_t *)pp_msg_v1, pp_msg_v1_len, &hex_str_msg));
    free(hex_str_msg);
    return pp_msg_v1;
}

/*****************************************************************/
/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 4 bytes.                                         */
/*    Poly    : 0x1EDC6F41L                                      */
/*    Reverse : TRUE.                                            */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams                        */
/* (ross@guest.adelaide.edu.au.). This document is likely to be  */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft".        */
/*                                                               */
/*****************************************************************/

static uint32_t crctable[256] = {
 0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
 0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
 0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
 0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
 0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
 0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
 0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
 0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
 0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
 0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
 0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
 0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
 0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
 0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
 0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
 0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
 0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
 0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
 0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
 0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
 0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
 0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
 0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
 0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
 0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
 0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
 0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
 0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
 0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
 0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
 0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
 0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
 0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
 0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
 0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
 0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
 0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
 0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
 0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
 0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
 0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
 0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
 0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
 0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
 0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
 0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
 0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
 0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
 0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
 0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
 0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
 0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
 0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
 0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
 0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
 0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
 0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
 0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
 0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
 0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
 0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
 0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
 0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
 0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

static uint32_t crc32c(uint8_t *buf, uint32_t len)
{
    uint32_t crc = 0xffffffff;
    while (len-- > 0)
    {
        crc = (crc >> 8) ^ crctable[(crc ^ (*buf++)) & 0xFF];
    }
    return crc^0xffffffff;
}

/* Verifies and parses a version 2 PROXY message */
static bool ppv2_parse(const uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info)
{
    uint8_t *proxy_msg = (uint8_t *) pkt;
    proxy_hdr_v2_t *proxy_hdr = (proxy_hdr_v2_t *) pkt;

    /* Constant 12 bytes block containing the protocol signature */
    if (memcmp(proxy_hdr->sig, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", sizeof(proxy_hdr->sig)))
    {
        fprintf(stderr, "Invalid v2 PROXY message: wrong protocol signature");
        return false;
    }

    /* The next byte (the 13th one) is the protocol version and command */
    if (proxy_hdr->ver_cmd != 0x21)
    {
        fprintf(stderr, "Invalid v2 PROXY message: wrong protocol version or command: %d. Only 0x21 is accepted!", proxy_hdr->ver_cmd);
        return false;
    }

    /*
     * The 14th byte contains the transport protocol and address family
     * \x11 : TCP over IPv4
     * \x21 : TCP over IPv6
     */
    sa_family_t sa_family = AF_UNSPEC;
    if (proxy_hdr->fam == '\x11')
    {
        sa_family = AF_INET;
    }
    else if (proxy_hdr->fam == '\x21')
    {
        sa_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "Invalid v2 PROXY message: wrong  transport protocol or address family: %d. Only \x11, \x21 are accepted", proxy_hdr->fam);
        return false;
    }

    /* The 15th and 16th bytes is the address length in bytes in network byte order */
    uint16_t len = ntohs(proxy_hdr->len);
    if (pktlen < sizeof(proxy_hdr_v2_t) + len)
    {
        fprintf(stderr, "Invalid v2 PROXY message: length is %u bytes but packet read/peeked is only %u bytes", len, pktlen);
        return false;
    }
    char *hex_str = NULL;
    fprintf(stderr, "v2 PROXY message: %s",  byte_array_to_hex_str(proxy_msg, sizeof(proxy_hdr_v2_t) + len, &hex_str));
    free(hex_str);

    /*
     * Starting from the 17th byte, addresses are presented in network byte order
     * The address order is always the same :
     * - source layer 3 address in network byte order
     * - destination layer 3 address in network byte order
     * - source layer 4 address if any, in network byte order (port)
     * - destination layer 4 address if any, in network byte order (port)
     */
    pkt += sizeof(proxy_hdr_v2_t);
    proxy_addr_t *addr = (proxy_addr_t *) pkt;
    uint16_t tlv_vectors_len = 0;
    if (sa_family == AF_INET && len >= sizeof(addr->ipv4_addr))
    {
        if (!inet_ntop(sa_family, &addr->ipv4_addr.src_addr, proxy_info->src_ip_str, sizeof(ip_str_t))
         || !inet_ntop(sa_family, &addr->ipv4_addr.dst_addr, proxy_info->dst_ip_str, sizeof(ip_str_t)))
        {
            fprintf(stderr, "Invalid v2 PROXY message: inet_ntop() failed for source/destination address: %s", strerror(errno));
            return false;
        }

        /* Ignore message if it is a health check */
        if (addr->ipv4_addr.src_addr == addr->ipv4_addr.dst_addr)
        {
            fprintf(stderr, "v2 PROXY message is just a health check. Ignoring!");
            return false;
        }

        proxy_info->src_port = ntohs(addr->ipv4_addr.src_port);
        proxy_info->dst_port = ntohs(addr->ipv4_addr.dst_port);

        pkt += sizeof(addr->ipv4_addr);
        tlv_vectors_len = len - sizeof(addr->ipv4_addr);
    }
    else if (sa_family == AF_INET6 && len >= sizeof(addr->ipv6_addr))
    {
        if (!inet_ntop(sa_family, &addr->ipv6_addr.src_addr, proxy_info->src_ip_str, sizeof(ip_str_t))
         || !inet_ntop(sa_family, &addr->ipv6_addr.dst_addr, proxy_info->dst_ip_str, sizeof(ip_str_t)))
        {
            fprintf(stderr, "Invalid v2 PROXY message: inet_ntop() failed for source/destination address: %s", strerror(errno));
            return false;
        }

        /* Ignore message if it is a health check */
        if (!memcmp(addr->ipv6_addr.src_addr, addr->ipv6_addr.dst_addr, 16))
        {
            fprintf(stderr, "v2 PROXY message is just a health check. Ignoring!");
            return false;
        }

        proxy_info->src_port = ntohs(addr->ipv6_addr.src_port);
        proxy_info->dst_port = ntohs(addr->ipv6_addr.dst_port);

        pkt += sizeof(addr->ipv6_addr);
        tlv_vectors_len = len - sizeof(addr->ipv6_addr);
    }
    else
    {
        fprintf(stderr, "Invalid v2 PROXY message: payload's length is %u bytes instead of at least %u bytes required for IPv%s",
                len, (uint16_t) (sa_family == AF_INET ? sizeof(addr->ipv4_addr) : sizeof(addr->ipv6_addr)), sa_family == AF_INET ? "4" : "6");
        return false;
    }

    /* TLVs */
    /* Any TLV vector must be at least 3 bytes */
    while (tlv_vectors_len > 3)
    {
        pp2_tlv_t *pp2_tlv = (pp2_tlv_t *) pkt;
        uint16_t pp2_tlv_len = pp2_tlv->length_hi << 8 | pp2_tlv->length_lo;
        uint16_t pp2_tlv_offset = 3 + pp2_tlv_len;
        if (pp2_tlv_offset > tlv_vectors_len)
        {
            fprintf(stderr, "Invalid v2 PROXY message: TLV vector's %#.2hhx length issue", pp2_tlv->type);
            return false;
        }
        fprintf(stderr, "TLV: Type %#.2hhx - Length %hu", pp2_tlv->type, pp2_tlv_len);
        switch (pp2_tlv->type)
        {
        case PP2_TYPE_ALPN:
        case PP2_TYPE_AUTHORITY:
            fprintf(stderr, "Ignoring TLV vector %#.2hhx", pp2_tlv->type);
            break;
        case PP2_TYPE_CRC32C:
        {
            if (pp2_tlv_len != sizeof(uint32_t))
            {
                fprintf(stderr, "Invalid v2 PROXY message: invalid PP2_TYPE_CRC32C TLV. Length is %hu instead of 4", pp2_tlv_len);
                return false;
            }
            uint32_t crc32c_chksum;
            memcpy(&crc32c_chksum, pp2_tlv->value, pp2_tlv_len);
            crc32c_chksum = ntohl(crc32c_chksum);

            memset(pp2_tlv->value, 0, pp2_tlv_len);
            uint32_t crc32c_cacl = crc32c(proxy_msg, sizeof(proxy_hdr_v2_t) + len);
            fprintf(stderr, "Received CRC32C checksum is %u. Calculated CRC32C checksum is %u", crc32c_chksum, crc32c_cacl);
            if (crc32c_chksum != crc32c_cacl)
            {
                fprintf(stderr, "Invalid v2 PROXY message: CRC32C checksum is invalid");
                return false;
            }
            break;
        }
        case PP2_TYPE_NOOP:
        case PP2_TYPE_SSL:
        case PP2_SUBTYPE_SSL_VERSION:
        case PP2_SUBTYPE_SSL_CN:
        case PP2_SUBTYPE_SSL_CIPHER:
        case PP2_SUBTYPE_SSL_SIG_ALG:
        case PP2_SUBTYPE_SSL_KEY_ALG:
        case PP2_TYPE_NETNS:
            fprintf(stderr, "Ignoring TLV vector %#.2hhx", pp2_tlv->type);
            break;
        case PP2_TYPE_AWS:
        {
            if (pp2_tlv_len < sizeof(pp2_tlv_aws_t))
            {
                fprintf(stderr, "Invalid v2 PROXY message: invalid PP2_TYPE_AWS TLV. Length is %hu which is less than the minimum %zu", pp2_tlv_len, sizeof(pp2_tlv_aws_t));
                return false;
            }
            pp2_tlv_aws_t *pp2_tlv_aws = (pp2_tlv_aws_t *) pp2_tlv->value;
            if (pp2_tlv_aws->type == PP2_SUBTYPE_AWS_VPCE_ID)
            {
                char *vpce_id = malloc(pp2_tlv_len);
                memcpy(vpce_id, pp2_tlv_aws->value, pp2_tlv_len - 1);
                vpce_id[pp2_tlv_len-1] = '\0';
                fprintf(stderr, "Connection is done through Private Link/Interface VPC endpoint %s", vpce_id);
                free(vpce_id);
            }
            break;
        }
        default:
            fprintf(stderr, "Ignoring unknown TLV vector %#.2hhx", pp2_tlv->type);
            break;
        }
        pkt += pp2_tlv_offset; tlv_vectors_len -= pp2_tlv_offset;
    }

    fprintf(stderr, "ELB %s:%hu Client %s:%hu", proxy_info->dst_ip_str, proxy_info->dst_port, proxy_info->src_ip_str, proxy_info->src_port);
    return true;
}

/* Verifies and parses a version 1 PROXY message */
static bool ppv1_parse(const uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info)
{
    uint32_t pkt_str_length = pktlen + 1;
    /* C-string to work with */
    char pkt_str[pkt_str_length];
    memcpy(pkt_str, pkt, pktlen);
    pkt_str[pktlen] = '\0';

    char *ptr = strstr(pkt_str, crlf);
    if (!ptr)
    {
        fprintf(stderr, "Invalid v1 PROXY message: \"\\r\\n\" is missing");
        return false;
    }
    *ptr = '\0';
    fprintf(stderr, "v1 PROXY message: %s", pkt_str);
    uint8_t index = 0;

    /* PROXY */
    char *protocol_sig = strtok(pkt_str, " ");
    if (!protocol_sig || strcmp(protocol_sig, "PROXY"))
    {
        fprintf(stderr, "Invalid v1 PROXY message: \"PROXY\" is missing");
        return false;
    }
    index += strlen("PROXY");

    /* Exactly one space */
    if (pkt[index] != '\x20')
    {
        fprintf(stderr, "Invalid v1 PROXY message: a space is missing between PROXY and the inet family");
        return false;
    }
    index++;

    /* String indicating the proxied INET protocol and family */
    char *inet_family = strtok(NULL, " ");
    if (!inet_family)
    {
        fprintf(stderr, "Invalid v1 PROXY message: inet protocol/family does not exists");
        return false;
    }
    sa_family_t sa_family = AF_UNSPEC;
    if (!strcmp(inet_family, "TCP4"))
    {
        sa_family = AF_INET;
    }
    else if (!(strcmp(inet_family, "TCP6")))
    {
        sa_family = AF_INET6;
    }
    else if (!(strcmp(inet_family, "UNKNOWN")))
    {
        fprintf(stderr, "Invalid v1 PROXY message: message indicates the proxied inet family as UNKNOWN");
        return false;
    }
    else
    {
        fprintf(stderr, "Invalid v1 PROXY message: wrong inet protocol/family: %s", inet_family);
        return false;
    }
    index += strlen(inet_family);

    /* Exactly one space */
    if (pkt[index] != '\x20')
    {
        fprintf(stderr, "Invalid v1 PROXY message: a space is missing between the inet family and the src_address");
        return false;
    }
    index++;

    /* Source address */
    char *src_address = strtok(NULL, " ");
    struct in6_addr src_sin_addr;
    if (!src_address || inet_pton(sa_family, src_address, &src_sin_addr) != 1)
    {
        fprintf(stderr, "Invalid v1 PROXY message: invalid source address %s", src_address);
        return false;
    }
    memcpy(proxy_info->src_ip_str, src_address, sizeof(proxy_info->src_ip_str));
    index += strlen(src_address);

    /* Exactly one space */
    if (pkt[index] != '\x20')
    {
        fprintf(stderr, "Invalid v1 PROXY message: a space is missing between the src_address and the dst_address");
        return false;
    }
    index++;

    /* Destination address */
    char *dst_address = strtok(NULL, " ");
    struct in6_addr dst_sin_addr;
    if (!dst_address || inet_pton(sa_family, dst_address, &dst_sin_addr) != 1)
    {
        fprintf(stderr, "Invalid v1 PROXY message: invalid destination address %s", dst_address);
        return false;
    }
    memcpy(proxy_info->dst_ip_str, dst_address, sizeof(proxy_info->dst_ip_str));
    index += strlen(dst_address);

    /* Ignore message if it is a health check */
    if (!strcmp(src_address, dst_address))
    {
        fprintf(stderr, "v1 PROXY message is just a health check. Ignoring!");
        return false;
    }

    /* Exactly one space */
    if (pkt[index] != '\x20')
    {
        fprintf(stderr, "Invalid v1 PROXY message: a space is missing between the dst_address and the src_port");
        return false;
    }
    index++;

    /* TCP source port represented as a decimal integer in the range [0..65535] inclusive */
    char *src_port_str = strtok(NULL, " ");
    if (!src_port_str || !parse_port(src_port_str, &proxy_info->src_port))
    {
        fprintf(stderr, "Invalid v1 PROXY message: invalid source port number %s", src_port_str);
        return false;
    }
    index += strlen(src_port_str);

    /* Exactly one space */
    if (pkt[index] != '\x20')
    {
        fprintf(stderr, "Invalid v1 PROXY message: a space is missing between the src_port and the dst_port");
        return false;
    }
    index++;

    /* TCP destination port represented as a decimal integer in the range [0..65535] inclusive */
    char *dst_port_str = strtok(NULL, " ");
    if (!dst_port_str || !parse_port(dst_port_str, &proxy_info->dst_port))
    {
        fprintf(stderr, "Invalid v1 PROXY message: invalid destination port number %s", dst_port_str);
        return false;
    }
    index += strlen(dst_port_str);

    /* The CRLF sequence */
    if (pkt[index++] != '\r' || pkt[index] != '\n')
    {
        fprintf(stderr, "Invalid v1 PROXY message: CRLF is not directly after dst_port");
        return false;
    }

    fprintf(stderr, "ELB %s:%hu Client %s:%hu", proxy_info->dst_ip_str, proxy_info->dst_port, proxy_info->src_ip_str, proxy_info->src_port);
    return true;
}

bool pp_parse(const uint8_t *pkt, uint32_t pktlen, pp_info_t *proxy_info)
{
    if (pktlen > 16 && !memcmp(pkt, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21", 13))
    {
        return ppv2_parse(pkt, pktlen, proxy_info);
    }
    else if (pktlen > 8 && !memcmp(pkt, "\x50\x52\x4F\x58\x59", 5))
    {
        return ppv1_parse(pkt, pktlen, proxy_info);;
    }
    else
    {
        return 0;
    }
}
