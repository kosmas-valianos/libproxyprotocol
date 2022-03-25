# libproxyprotocol
An ANSI C library to parse and create [PROXY protocol](https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt) v1 and v2 headers
* Full coverage of the latest 2.6 specification in parsing all the v2 TLVs, including the custom ones from AWS and Azure.
* Easy access of the values of the extracted v2 TLVs though the API. In case the v2 TLV values are US-ASCII string name, they are given as proper NULL terminated strings for easy usage.
* Socket free logic. Does not hook, manipulate, assume any networking. It merely works on buffers.
* Compilable with most compilers and usable at any platform as it is written in ANSI C.

## Installation
The library should be compilable to any platform as it is written in ANSI C. It comes with a Makefile which can create the shared library `libproxyprotocol.so` which can then be linked to your application. Special care has been taken to make it work with Windows as well. In that case you have to compile it to a .dll/.lib yourself. In case of Windows remember that you have to link with the `ws2_32.lib`. An example of this is shown in tests.

## API
### Parsing
**`int32_t pp_parse_hdr(uint8_t *buffer, uint32_t buffer_length, pp_info_t *pp_info)`**:

Inpects the buffer for a PROXY protocol header and extracts all the information if any.
* `buffer`:         Pointer to a buffer with the data to parse. Normally it will be the buffer used to peek data from a socket.
* `buffer_length`:  Buffer's length. Typically the bytes read from the `recv(MSG_PEEK)` operation.
* `pp_info`:        Pointer to a `pp_info_t` structure which will get filled with all the extracted information.
* `return`:
   * \> 0 Length of the PROXY protocol header
   * == 0 No PROXY protocol header found
   * <  0 Error occurred. `pp_strerror()` with that value can be used to get a descriptive message

You shall not pass your `pp_info_t` variable to `pp_parse()` again without first clearing it with `pp_info_clear()`

**`void pp_info_clear(pp_info_t *pp_info)`**

Clears the `pp_info_t` structure and frees any allocated memory associated with it. Shall always be called after a call to `pp_parse()`
* `pp_info`: Pointer to a filled `pp_info_t` structure which has been used to a previous call to `pp_parse()`

**`const uint8_t *pp_info_get_*(const pp_info_t *pp_info, uint16_t *length);`**

Searches for the specified TLV and returns its value
* `pp_info` Pointer to a `pp_info_t` structure used in `pp_parse()`
* `length`  Pointer to a `uint16_t` where the TLV's value length will be set
* `return`  Pointer to a buffer holding the TLV's value if found else `NULL`. In case of US-ASCII value the buffer is `NULL` terminated

### Creating
**`uint8_t *pp_create_hdr(uint8_t version, const pp_info_t *pp_info, uint16_t *pp_hdr_len, int32_t *error)`**:

Creates a PROXY protocol header considering the information inside the pp_info.
* `version`:
   * 0 Create a v1 PROXY protocol header.
   * 1 Create a v2 PROXY protocol header.
* `pp_info`:    Pointer to a filled `pp_info_t` structure whose information will be used for the creation of the PROXY protocol header.
* `pp_hdr_len`: Pointer to a `uint16_t` where the length of the create PROXY protocol header will be set
* `error`:      Pointer to a `int32_t` where the error value will be set
   * `ERR_NULL` No error occurred
   * < 0        Error
* `return`: Pointer to a heap allocated buffer containing the PROXY protocol header. Must be freed with free()

### Error reporting
**`const char *pp_strerror(int32_t error)`**

Returns a descriptive error message
* `error`:  `int32_t` value from other API functions
* `return`: Pointer to the descriptive message if the error value is recognized else `NULL`

## Example
See `examples/client_server.c`

## In progress
* Creating v2 PROXY protocol headers with TLVs is not yet supported. Will be added in the next major release
