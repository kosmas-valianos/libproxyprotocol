#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "proxy_protocol.h"

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

#define PP1_MAX_LENGHT 108
static const char *crlf = "\r\n";

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

typedef struct
{
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[1];
} pp2_tlv_t;

typedef struct
{
    uint8_t   client;
    uint32_t  verify;
    pp2_tlv_t sub_tlv[1];
} pp2_tlv_ssl_t;

typedef struct
{
    uint8_t type;
    uint8_t value[1];
} pp2_tlv_aws_t;

typedef struct
{
    uint8_t  type;
    uint32_t linkid;
} pp2_tlv_azure_t;

/****************************************************************/

#pragma pack()

static const char *errors[] = {
    "No error",
    "Invalind PROXY protocol version given. Only 1 and 2 are valid",
    "Invalid v2 PROXY message: wrong protocol signature",
    "Invalid v2 PROXY message: wrong protocol version",
    "Invalid v2 PROXY message: wrong command",
    "Invalid v2 PROXY message: wrong transport protocol or address family",
    "Invalid v2 PROXY message: length",
    "Invalid v2 PROXY message: invalid IPv4 src IP",
    "Invalid v2 PROXY message: invalid IPv4 dst IP"
    "Invalid v2 PROXY message: invalid IPv6 src IP",
    "Invalid v2 PROXY message: invalid IPv6 dst IP",
    "Invalid v2 PROXY message: invalid TLV vector's length",
    "Invalid v2 PROXY message: invalid PP2_TYPE_CRC32C",
    "Invalid v2 PROXY message: invalid PP2_TYPE_UNIQUE_ID",
    "Invalid v2 PROXY message: invalid PP2_TYPE_AWS",
    "Invalid v2 PROXY message: invalid PP2_TYPE_AZURE",
    "Invalid v1 PROXY message: \"\\r\\n\" is missing",
    "Invalid v1 PROXY message: \"PROXY\" is missing",
    "Invalid v1 PROXY message: space is missing",
    "Invalid v1 PROXY message: wrong transport protocol or address family",
    "Invalid v1 PROXY message: invalid IPv4 src IP",
    "Invalid v1 PROXY message: invalid IPv4 dst IP"
    "Invalid v1 PROXY message: invalid IPv6 src IP",
    "Invalid v1 PROXY message: invalid IPv6 dst IP",
    "Invalid v1 PROXY message: invalid src port",
    "Invalid v1 PROXY message: invalid dst port",
};

const char *pp_strerror(uint32_t error)
{
    if (error > ERR_PP1_DST_PORT)
    {
        return NULL;
    }
    return errors[error];
}

static bool parse_port(const char *value, uint16_t *usport)
{
    uint64_t port = strtoul(value, NULL, 10);
    if (port == 0 || port > UINT16_MAX)
    {
        return false;
    }
    *usport = (uint16_t) port;
    return true;
}

static tlv_t *tlv_new(uint8_t type, uint16_t length, const void *value)
{
    tlv_t *tlv = malloc(sizeof(tlv_t) - 1 + length);
    tlv->type = type;
    tlv->length = length;
    memcpy(tlv->value, value, length);
    return tlv;
}

static void tlv_array_append_tlv(tlv_array_t *tlv_array, tlv_t *tlv)
{
    if (!tlv_array->tlvs)
    {
        tlv_array->len = 0;
        tlv_array->size = 10;
        tlv_array->tlvs = malloc(tlv_array->size * sizeof(tlv_t*));
    }

    if (tlv_array->size == tlv_array->len)
    {
        tlv_array->size += 5;
        tlv_array->tlvs = realloc(tlv_array->tlvs, tlv_array->size * sizeof(tlv_t*));
    }

    tlv_array->len++;
    tlv_array->tlvs[tlv_array->len - 1] = tlv;
}

static void tlv_array_clear(tlv_array_t *tlv_array)
{
    uint32_t i;
    for (i = 0; i < tlv_array->len; i++)
    {
        free(tlv_array->tlvs[i]);
        tlv_array->tlvs[i] = NULL;
    }
    tlv_array->len = 0;
    tlv_array->size = 0;
    free(tlv_array->tlvs);

}

uint8_t *pp_info_get_tlv_value(const pp_info_t *pp_info, uint8_t type, uint8_t subtype, uint16_t *value_len_out)
{
    *value_len_out = 0;
    if (!pp_info->tlv_array.tlvs || !pp_info->tlv_array.len)
    {
        return NULL;
    }

    uint32_t i;
    for (i = 0; i < pp_info->tlv_array.len; i++)
    {
        tlv_t *tlv = pp_info->tlv_array.tlvs[i];
        if (tlv->type == type)
        {
            if (subtype > 0)
            {
                if (tlv->value[0] == subtype)
                {
                    *value_len_out = tlv->length - 1;
                    return &tlv->value[1];
                }
                return NULL;
            }
            *value_len_out = tlv->length;
            return tlv->value;
        }
    }
    return NULL;
}

void pp_info_clear(pp_info_t *pp_info)
{
    tlv_array_clear(&pp_info->tlv_array);
    memset(pp_info, 0, sizeof(*pp_info));
}

uint8_t *pp2_create_msg(uint8_t fam, const pp_info_t *pp_info, uint32_t *pp2_msg_len, uint32_t *error)
{
    typedef struct
    {
        proxy_hdr_v2_t proxy_hdr_v2;
        proxy_addr_t   proxy_addr;
    } proxy_message_v2_t;

    proxy_message_v2_t msg = {
            .proxy_hdr_v2.sig = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",
            .proxy_hdr_v2.ver_cmd = pp_info->v2local ? '\x20' : '\x21',
    };

    uint16_t len;
    uint8_t transport_protocol = fam & 0x0f;
    if (transport_protocol != 0x0 && transport_protocol != 0x1 && transport_protocol != 0x2)
    {
        return NULL;
    }
    uint8_t address_family = fam >> 4;
    if (address_family == 0x0)
    {
        len = 0;
        if (!pp_info->v2local)
        {
            return NULL;
        }
    }
    else if (address_family == 0x1)
    {
        len = 12;
        if (inet_pton(AF_INET, pp_info->src_addr, &msg.proxy_addr.ipv4_addr.src_addr) != 1)
        {
            *error = ERR_PP2_IPV4_SRC_IP;
            return NULL;
        }
        if (inet_pton(AF_INET, pp_info->dst_addr, &msg.proxy_addr.ipv4_addr.dst_addr) != 1)
        {
            *error = ERR_PP2_IPV4_DST_IP;
            return NULL;
        }
        msg.proxy_addr.ipv4_addr.src_port = htons(pp_info->src_port);
        msg.proxy_addr.ipv4_addr.dst_port = htons(pp_info->dst_port);
    }
    else if (address_family == 0x2)
    {
        len = 36;
        if (inet_pton(AF_INET6, pp_info->src_addr, &msg.proxy_addr.ipv6_addr.src_addr) != 1)
        {
            *error = ERR_PP2_IPV6_SRC_IP;
            return NULL;
        }
        if (inet_pton(AF_INET6, pp_info->dst_addr, &msg.proxy_addr.ipv6_addr.dst_addr) != 1)
        {
            *error = ERR_PP2_IPV6_DST_IP;
            return NULL;
        }
        msg.proxy_addr.ipv6_addr.src_port = htons(pp_info->src_port);
        msg.proxy_addr.ipv6_addr.dst_port = htons(pp_info->dst_port);
    }
    else if (address_family == 0x3)
    {
        len = 216;
        memcpy(msg.proxy_addr.unix_addr.src_addr, pp_info->src_addr, sizeof(pp_info->src_addr));
        memcpy(msg.proxy_addr.unix_addr.dst_addr, pp_info->dst_addr, sizeof(pp_info->dst_addr));
    }
    else
    {
        return NULL;
    }
    msg.proxy_hdr_v2.fam = fam;
    msg.proxy_hdr_v2.len = htons(len);

    /* Serialize the msg */
    *pp2_msg_len = sizeof(proxy_hdr_v2_t) + len;
    uint8_t *pp2_msg = malloc(*pp2_msg_len);
    memcpy(pp2_msg, &msg.proxy_hdr_v2, sizeof(proxy_hdr_v2_t));
    memcpy(pp2_msg + sizeof(proxy_hdr_v2_t), &msg.proxy_addr, len);

    *error = ERR_NULL;
    return pp2_msg;
}

static uint8_t *pp1_create_msg(uint8_t fam, const pp_info_t *pp_info, uint32_t *pp1_msg_len, uint32_t *error)
{
    if (fam != AF_INET && fam != AF_INET6)
    {
        return NULL;
    }
    char block[PP1_MAX_LENGHT];
    /* sprintf() as snprintf does not exist in ANSI C */
    if (strlen(pp_info->src_addr) > 39 || strlen(pp_info->dst_addr) > 39)
    {
        return NULL;
    }
    char src_addr[39+1];
    char dst_addr[39+1];
    memcpy(src_addr, pp_info->src_addr, sizeof(src_addr));
    memcpy(dst_addr, pp_info->dst_addr, sizeof(dst_addr));
    *pp1_msg_len = sprintf(block, "PROXY %s %s %s %hu %hu%s",
        fam == AF_INET ? "TCP4" : "TCP6", src_addr, dst_addr, pp_info->src_port, pp_info->dst_port, crlf);
    uint8_t *pp1_msg = malloc(*pp1_msg_len);
    memcpy(pp1_msg, block, *pp1_msg_len);
    *error = ERR_NULL;
    return pp1_msg;
}

uint8_t *pp_create_msg(uint8_t version, uint8_t fam, const pp_info_t *pp_info, uint32_t *pp_msg_len, uint32_t *error)
{
    if (version == 1)
    {
        return pp1_create_msg(fam, pp_info, pp_msg_len, error);
    }
    else if (version == 2)
    {
        return pp2_create_msg(fam, pp_info, pp_msg_len, error);
    }
    else
    {
        *error = ERR_PP_VERSION;
        return NULL;
    }
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

static uint32_t crc32c(const uint8_t *buf, uint32_t len)
{
    uint32_t crc = 0xffffffff;
    while (len-- > 0)
    {
        crc = (crc >> 8) ^ crctable[(crc ^ (*buf++)) & 0xFF];
    }
    return crc^0xffffffff;
}

/* Verifies and parses a version 2 PROXY message */
static int ppv2_parse(uint8_t *pkt, uint32_t pktlen, pp_info_t *pp_info)
{
    uint8_t *proxy_msg = pkt;
    proxy_hdr_v2_t *proxy_hdr = (proxy_hdr_v2_t *) pkt;

    /* Constant 12 bytes block containing the protocol signature */
    if (memcmp(proxy_hdr->sig, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", sizeof(proxy_hdr->sig)))
    {
        return ERR_PP2_SIG;
    }

    /* The next byte (the 13th one) is the protocol version and command */
    /* The highest four bits contains the version. Only \x2 is accepted */
    uint8_t version = proxy_hdr->ver_cmd >> 4;
    if (version != 0x2)
    {
        return ERR_PP2_VERSION;
    }
    /* The lowest four bits represents the command
     * \x0 : LOCAL
     * \x1 : PROXY
     */
    uint8_t cmd = proxy_hdr->ver_cmd & 0x0f;
    if (cmd == 0x0)
    {
        pp_info->v2local = 1;
    }
    else if (cmd == 0x1)
    {
        pp_info->v2local = 0;
    }
    else
    {
        return ERR_PP2_CMD;
    }

    /*
     * The 14th byte contains the transport protocol and address family
     * \x00 : UNSPEC
     * \x11 : TCP over IPv4
     * \x12 : UDP over IPv4
     * \x21 : TCP over IPv6
     * \x22 : UDP over IPv6
     * \x31 : UNIX stream
     * \x32 : UNIX datagram
     */
    uint8_t fam;
    if (proxy_hdr->fam == '\x00' || cmd == 0x0)
    {
        fam = AF_UNSPEC;
    }
    else if (proxy_hdr->fam == '\x11' || proxy_hdr->fam == '\x12')
    {
        fam = AF_INET;
    }
    else if (proxy_hdr->fam == '\x21' || proxy_hdr->fam == '\x22')
    {
        fam = AF_INET6;
    }
    else if (proxy_hdr->fam == '\x31' || proxy_hdr->fam == '\x32')
    {
        fam = AF_UNIX;
    }
    else
    {
        return ERR_PP2_TRANSPORT_FAMILY;
    }

    /* The 15th and 16th bytes is the address length in bytes in network byte order */
    uint16_t len = ntohs(proxy_hdr->len);
    if (pktlen < sizeof(proxy_hdr_v2_t) + len)
    {
        return ERR_PP2_LENGTH;
    }

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
    if (fam == AF_UNSPEC)
    {
        tlv_vectors_len = len;
    }
    else if (fam == AF_INET && len >= sizeof(addr->ipv4_addr))
    {
        if (!inet_ntop(fam, &addr->ipv4_addr.src_addr, pp_info->src_addr, sizeof(pp_info->src_addr)))
        {
            return ERR_PP2_IPV4_SRC_IP;
        }
        if (!inet_ntop(fam, &addr->ipv4_addr.dst_addr, pp_info->dst_addr, sizeof(pp_info->dst_addr)))
        {
            return ERR_PP2_IPV4_DST_IP;
        }

        pp_info->src_port = ntohs(addr->ipv4_addr.src_port);
        pp_info->dst_port = ntohs(addr->ipv4_addr.dst_port);

        pkt += sizeof(addr->ipv4_addr);
        tlv_vectors_len = len - sizeof(addr->ipv4_addr);
    }
    else if (fam == AF_INET6 && len >= sizeof(addr->ipv6_addr))
    {
        if (!inet_ntop(fam, &addr->ipv6_addr.src_addr, pp_info->src_addr, sizeof(pp_info->src_addr)))
        {
            return ERR_PP2_IPV6_SRC_IP;
        }
        if (!inet_ntop(fam, &addr->ipv6_addr.dst_addr, pp_info->dst_addr, sizeof(pp_info->dst_addr)))
        {
            return ERR_PP2_IPV6_DST_IP;
        }

        pp_info->src_port = ntohs(addr->ipv6_addr.src_port);
        pp_info->dst_port = ntohs(addr->ipv6_addr.dst_port);

        pkt += sizeof(addr->ipv6_addr);
        tlv_vectors_len = len - sizeof(addr->ipv6_addr);
    }
    else if (fam == AF_UNIX && len >= sizeof(addr->unix_addr))
    {
        memcpy(pp_info->src_addr, addr->unix_addr.src_addr, sizeof(addr->unix_addr.src_addr));
        memcpy(pp_info->dst_addr, addr->unix_addr.dst_addr, sizeof(addr->unix_addr.dst_addr));
    }
    else
    {
        return ERR_PP2_LENGTH;
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
            return ERR_PP2_TLV_LENGTH;
        }

        switch (pp2_tlv->type)
        {
        case PP2_TYPE_ALPN:
        {
            tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len, pp2_tlv->value);
            tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            break;
        }
        case PP2_TYPE_AUTHORITY:
        case PP2_TYPE_NETNS:
        {
            /* +1 to save it as a string */
            tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len + 1, pp2_tlv->value);
            tlv->value[pp2_tlv_len] = '\0';
            tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            break;
        }
        case PP2_TYPE_CRC32C:
        {
            if (pp2_tlv_len != sizeof(uint32_t))
            {
                return ERR_PP2_TYPE_CRC32C;
            }
            uint32_t crc32c_chksum;
            memcpy(&crc32c_chksum, pp2_tlv->value, pp2_tlv_len);
            crc32c_chksum = ntohl(crc32c_chksum);

            memset(pp2_tlv->value, 0, pp2_tlv_len);
            uint32_t crc32c_calculated = crc32c(proxy_msg, sizeof(proxy_hdr_v2_t) + len);
            if (crc32c_chksum != crc32c_calculated)
            {
                return ERR_PP2_TYPE_CRC32C;
            }

            tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len, &crc32c_chksum);
            tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            break;
        }
        case PP2_TYPE_NOOP:
            break;
        case PP2_TYPE_UNIQUE_ID:
        {
            if (pp2_tlv_len > 128)
            {
                return ERR_PP2_TYPE_UNIQUE_ID;
            }
            tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len, pp2_tlv->value);
            tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            break;
        }
        case PP2_TYPE_SSL:
            break;
        case PP2_TYPE_AWS:
        {
            if (pp2_tlv_len < sizeof(pp2_tlv_aws_t))
            {
                return ERR_PP2_TYPE_AWS;
            }
            pp2_tlv_aws_t *pp2_tlv_aws = (pp2_tlv_aws_t *) pp2_tlv->value;
            /* Connection is done through Private Link/Interface VPC endpoint */
            if (pp2_tlv_aws->type == PP2_SUBTYPE_AWS_VPCE_ID)
            {
                /* +1 to save it as a string. Example: \x1vpce-08d2bf15fac5001c9 */
                tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len + 1, pp2_tlv->value);
                tlv->value[pp2_tlv_len] = '\0';
                tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            }
            break;
        }
        case PP2_TYPE_AZURE:
        {
            if (pp2_tlv_len < sizeof(pp2_tlv_azure_t))
            {
                return ERR_PP2_TYPE_AZURE;
            }
            pp2_tlv_azure_t *pp2_tlv_azure = (pp2_tlv_azure_t *) pp2_tlv->value;
            /* Connection is done through Private Link service */
            if (pp2_tlv_azure->type == PP2_TYPE_AZURE)
            {
                tlv_t *tlv = tlv_new(pp2_tlv->type, pp2_tlv_len, pp2_tlv->value);
                tlv_array_append_tlv(&pp_info->tlv_array, tlv);
            }
            break;
        }
        default:
            break;
        }
        pkt += pp2_tlv_offset;
        tlv_vectors_len -= pp2_tlv_offset;
    }

    return sizeof(proxy_hdr_v2_t) + len;
}

/* Verifies and parses a version 1 PROXY message */
static int ppv1_parse(const uint8_t *pkt, uint32_t pktlen, pp_info_t *pp_info)
{
    char block[PP1_MAX_LENGHT] = { 0 };
    char *ptr = block;
    int length = 0;
    memcpy(block, pkt, pktlen < PP1_MAX_LENGHT ? pktlen : PP1_MAX_LENGHT);

    char *block_end = strstr(block, crlf);
    if (!block_end)
    {
        return ERR_PP1_CRLF;
    }
    block_end += strlen(crlf);
    length = block_end - block;

    /* PROXY */
    if (memcmp(block, "PROXY", 5))
    {
        return ERR_PP1_PROXY;
    }
    ptr += 5;

    /* Exactly one space */
    if (*ptr != '\x20')
    {
        return ERR_PP1_SPACE;
    }
    ptr++;

    /* String indicating the proxied INET protocol and family */
    char *inet_family = strchr(ptr, ' ');
    if (!inet_family)
    {
        /* Unknown connection (short form) */
        if (pktlen == 15 || !memcmp(ptr, "UNKNOWN", 7))
        {
            return length;
        }
        return ERR_PP1_TRANSPORT_FAMILY;
    }
    uint8_t sa_family = AF_UNSPEC;
    if (!memcmp(ptr, "TCP4", 4))
    {
        sa_family = AF_INET;
        ptr += 4;
    }
    else if (!memcmp(ptr, "TCP6", 4))
    {
        sa_family = AF_INET6;
        ptr += 4;
    }
    else if (!memcmp(ptr, "UNKNOWN", 7))
    {
        /* The receiver must ignore anything presented before the CRLF is found */
        return length;
    }
    else
    {
        return ERR_PP1_TRANSPORT_FAMILY;;
    }

    /* Exactly one space */
    if (*ptr != '\x20')
    {
        return ERR_PP1_SPACE;
    }
    ptr++;

    /* Source address */
    char *src_address_end = strchr(ptr, ' ');
    if (!src_address_end)
    {
        return sa_family == AF_INET ? ERR_PP1_IPV4_SRC_IP : ERR_PP1_IPV6_SRC_IP;
    }
    uint16_t src_address_length = src_address_end - ptr;
    memcpy(pp_info->src_addr, ptr, src_address_length);
    struct in6_addr src_sin_addr;
    if (inet_pton(sa_family, pp_info->src_addr, &src_sin_addr) != 1)
    {
        return sa_family == AF_INET ? ERR_PP1_IPV4_SRC_IP : ERR_PP1_IPV6_SRC_IP;
    }
    ptr += src_address_length;

    /* Exactly one space */
    if (*ptr != '\x20')
    {
        return ERR_PP1_SPACE;
    }
    ptr++;

    /* Destination address */
    char *dst_address_end = strchr(ptr, ' ');
    if (!dst_address_end)
    {
        return sa_family == AF_INET ? ERR_PP1_IPV4_DST_IP : ERR_PP1_IPV6_DST_IP;
    }
    uint16_t dst_address_length = dst_address_end - ptr;
    memcpy(pp_info->dst_addr, ptr, dst_address_length);
    struct in6_addr dst_sin_addr;
    if (inet_pton(sa_family, pp_info->dst_addr, &dst_sin_addr) != 1)
    {
        return sa_family == AF_INET ? ERR_PP1_IPV4_DST_IP : ERR_PP1_IPV6_DST_IP;
    }
    ptr += dst_address_length;

    /* Exactly one space */
    if (*ptr != '\x20')
    {
        return ERR_PP1_SPACE;
    }
    ptr++;

    /* TCP source port represented as a decimal integer in the range [0..65535] inclusive */
    char *src_port_end = strchr(ptr, ' ');
    if (!src_port_end)
    {
        return ERR_PP1_SRC_PORT;
    }
    char src_port_str[6] = { 0 };
    uint16_t src_port_length = src_port_end - ptr;
    memcpy(src_port_str, ptr, src_port_length);
    if (!parse_port(src_port_str, &pp_info->src_port))
    {
        return ERR_PP1_SRC_PORT;
    }
    ptr += src_port_length;

    /* Exactly one space */
    if (*ptr != '\x20')
    {
        return ERR_PP1_SPACE;
    }
    ptr++;

    /* TCP destination port represented as a decimal integer in the range [0..65535] inclusive */
    char *dst_port_end = strchr(ptr, '\r');
    if (!dst_port_end)
    {
        return ERR_PP1_DST_PORT;
    }
    char dst_port_str[6] = { 0 };
    uint16_t dst_port_length = dst_port_end - ptr;
    memcpy(dst_port_str, ptr, dst_port_length);
    if (!parse_port(dst_port_str, &pp_info->dst_port))
    {
        return ERR_PP1_DST_PORT;
    }
    ptr += dst_port_length;

    /* The CRLF sequence */
    if (*ptr != '\r' || *(ptr+1) != '\n')
    {
        return ERR_PP1_CRLF;
    }

    return length;
}

int pp_parse(uint8_t *pkt, uint32_t pktlen, pp_info_t *pp_info)
{
    memset(pp_info, 0, sizeof(*pp_info));
    if (pktlen >= 16 && !memcmp(pkt, "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A", 12))
    {
        return ppv2_parse(pkt, pktlen, pp_info);
    }
    else if (pktlen >= 8 && !memcmp(pkt, "\x50\x52\x4F\x58\x59", 5))
    {
        return ppv1_parse(pkt, pktlen, pp_info);;
    }
    else
    {
        return -1;
    }
}
