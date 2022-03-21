# libproxyprotocol
An ANSI C library to parse and create [PROXY protocol](https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt) v1 and v2 headers
* Full specification coverage of all the v2 TLVs, including the custom ones from AWS and Azure
* Easy access of the values of the extracted v2 TLVs though the API. In case the v2 TLV values are US-ASCII string name, they are given as proper NULL terminated strings for easy usage.
* Socket free logic. Does not hook, manipulate, assume any networking. It merely works on buffers.
* Compilable with most compilers and usable at any platform as it is written in ANSI C.

## Installation
The library should be compilable to any platform as it is written in ANSI C. It comes with a Makefile which can create the shared library `libproxyprotocol.so` which can then be linked to your application. Special care has been taken to make it work with Windows as well. In that case you have to compile it to a .dll/.lib yourself. In case of Windows remember that you have to link with the `ws2_32.lib`. An example of this is shown in tests.

## API
### Parsing
**`pp_parse()`**: parsing a PROXY protocol header. Parameters:
* `uint8_t *pkt`: Pointer to a buffer with the data to parse. Normally it will be the buffer used to peek data from a socket.
* `uint32_t pktlen`: Data's length. Normally it will be the return value of a `recv(MSG_PEEK)`.
* `pp_info_t *proxy_info`: Pointer to a `pp_info_t` variable which will be used to save all the extracted information of the PROXY protocol header including the TLVs
* `return value: int32_t`: The length of the PROXY protocol header in case of success or a negative integer in case of error. You can use `pp_strerror()` to get a descriptive error message. In case the data dont't match any of the v1/v2 signatures `0` is returned.

You shall not pass your `pp_info_t` variable to `pp_parse()` again without first clearing it with `pp_info_clear()` (see below)

**`pp_info_get_tlv_value()`**: extracting TLVs' values. Parameters:
* `pp_info_t *pp_info`: The `pp_info_t` used in the `pp_parse()`
* `uint8_t type`: The type of the TLV you are looking for as per the specification e.g. PP2_TYPE_AWS, PP2_TYPE_AZURE etc.
* `uint8_t subtype`: The subtype of the TLV you are looking for (in case it is needed else 0 to get it ignored) as per the specification e.g. PP2_SUBTYPE_AWS_VPCE_ID, PP2_SUBTYPE_AZURE_PRIVATEENDPOINT_LINKID
* `uint16_t *value_len_out`: The length of the value so that applications can copy and use the value properly
* `return value: uint8_t *`: Pointer to the value. In case the value is a string e.g. PP2_TYPE_AWS-PP2_SUBTYPE_AWS_VPCE_ID then the buffer is NULL terminated so that it can be used directly for string operations like `strcmp()` etc. **Do not manipulate these data in any way, rather make copies of them if you need to modify them.**

**`pp_info_clear()`**: clearing a `pp_info_t` structure. You **MUST** use it. Parameter:
* `pp_info_t *pp_info`: A pointer to the `pp_info_t` used in `pp_parse()`

It basically clears the saved TLVs structure. For v1 it is not really needed as there are not any TLVs but to be safe always use it! A PROXY protocol sender might change from v1 to v2 so better to have your application prepared.

### Creating
**`pp_create_hdr()`**: create a PROXY protocol header. Parameters:
* `uint8_t version`: `1` or `2` depending on the PROXY protocol version you want to use.
* `uint8_t fam`: Transport and address family. The values match exactly the specification:
  * v2 
    * `'\x00'` : UNSPEC
    * `'\x11'` : TCP over IPv4
    * `'\x12'` : UDP over IPv4
    * `'\x21'` : TCP over IPv6
    * `'\x22'` : UDP over IPv6
    * `'\x31'` : UNIX stream
    * `'\x32'` : UNIX datagram
  * v1
    * `AF_INET`
    * `AF_INET6`
* `pp_info_t *pp_info` : Pointer to a filled `pp_info_t` structure. Note that at the moment tlvs from the `tlv_array_t tlv_array` inside it will not be included in the header. This functionality will be added with the next release.
* `uint32_t *pp_hdr_len`: Output parameter where the length of the the PROXY protocol header will be stored.
* `uint32_t *error`: Outpur parameter where its value will be set to a negative integer in case of error or `ERR_NULL` in case of success. You can use `pp_strerror()` to get a descriptive error message
* `return value: uint8_t *`: Pointer to a dynamically allocated buffer where the PROXY protocol header exists. Shall be freed with `free()`

## Example
See `examples/client_server.c`

## In progress
* Creating v2 PROXY protocol headers with TLVs is not yet supported. Will be added in the next release
