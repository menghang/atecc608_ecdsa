#ifndef WPC_ROOT_CA_H
#define WPC_ROOT_CA_H

#ifdef __cplusplus
extern "C" {
#endif
#ifdef BASIC_TEST
#ifdef MORE_TEST
extern const char wpcca1_root_ca_base64[];
extern const size_t wpcca1_root_ca_base64_size;
#else
extern const uint8_t wpcca1_root_ca_digest[];
#endif
#endif
#ifdef __cplusplus
}
#endif

#endif
