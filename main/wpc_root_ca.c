
#include <stdio.h>
#include "config.h"

#ifdef BASIC_TEST
#ifdef MORE_TEST
const char wpcca1_root_ca_base64[] =
    "MIIBLDCB06ADAgECAgh3YRK0EUearDAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZX\r\n"
    "UENDQTEwIBcNMjEwMzAzMTYwNDAxWhgPOTk5OTEyMzEyMzU5NTlaMBExDzANBgNV\r\n"
    "BAMMBldQQ0NBMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABASEByCzo7F50Gx3\r\n"
    "raAARNLPIJvDPONEmgjGf4/1A3NjoEP1kHGQr7e88fymZ8tew+oZ+Wp7QR89jWMw\r\n"
    "SC1+KBKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgacC3\r\n"
    "FeLAavaI+bZHo49TZ9UCpvXeVbkFoQJavUJx9GgCIQCfX08/diCuF3TYBLxxmqGb\r\n"
    "UFW7ou1N5kD9VPo5W+1duA==";

const size_t wpcca1_root_ca_base64_size = sizeof(wpcca1_root_ca_base64) / sizeof(uint8_t);
#else
const uint8_t wpcca1_root_ca_digest[32] = {
    0xa1, 0x75, 0x9e, 0xcc, 0xa0, 0xbe, 0x3b, 0x85, 0x01, 0x18, 0x18, 0x3e, 0xd6, 0xcd, 0xd6, 0xd4,
    0xa5, 0xdb, 0x7d, 0x83, 0xe6, 0xfd, 0x0e, 0x6f, 0x47, 0x5c, 0xe4, 0xbb, 0x6e, 0xa0, 0x14, 0x24};
#endif
#endif
