/**
 * atecc608a_ecdsa example
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2020 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This is mbedtls boilerplate for library configuration */
#include "mbedtls/config.h"

/* System Includes*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

/* Cryptoauthlib includes */
#include "cryptoauthlib.h"
#include "mbedtls/atca_mbedtls_wrap.h"
#include "atcacert/atcacert_client.h"

/* mbedTLS includes */
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

#include "config.h"

/* certificates */
#include "wpc_root_ca.h"
#include "zcust_def_1_signer.h"
#include "zcust_def_2_device.h"

#define MAX_CERT_SIZE 400
#define MAX_CERT_CHAIN_SIZE 1024
#define NONCE_SIZE 16

#define AUTH_HEADER_CHALLENGE_AUTH 0x13
// #define AUTH_HEADER_GET_DIGESTS 0x19
// #define AUTH_HEADER_GET_CERTIFICATE 0x1A
#define AUTH_HEADER_CHALLENGE 0x1B

// #define AUTH_REQ_GET_DIGESTS_SIZE 2
// #define AUTH_REQ_GET_CERTIFICATE_SIZE 4
#define AUTH_REQ_CHALLENGE_SIZE (NONCE_SIZE + 2)

#define AUTH_TBS_AUTH_SIZE (1 + ATCA_SHA256_DIGEST_SIZE + AUTH_REQ_CHALLENGE_SIZE + 3)

#define ECDSA_SIG_SIZE 32

#define PVKEY_SLOT_NUM 0

static const char *TAG = "ATECC608";

#ifdef BASIC_TEST
typedef struct
{
    uint8_t cert_chain[MAX_CERT_CHAIN_SIZE]; // certificate chain
    uint16_t cert_chain_length;              // totoal certificate length
    uint16_t cert_rh_length;                 // root certificate hash length
    uint16_t cert_mc_lenth;                  // manufacturer CA certificate length
    uint16_t cert_puc_length;                // product unit certificate length
} cert_chain_t;

static cert_chain_t cert_chain_slot0;                             // certificate chain
static uint8_t cert_chain_digests_slot0[ATCA_SHA256_DIGEST_SIZE]; // certificate chain hash
#ifdef MORE_TEST
static uint8_t cert_chain_slot0_public_key[ATCA_ECCP256_PUBKEY_SIZE]; // public key
#endif

static void print_cert(const uint8_t *cert, const size_t cert_len);
#ifdef MORE_TEST
static void print_config_zone(void);
static int test_verify_certs(void);
static int atecc608_get_root_cert_hash(const char *cert_base64, size_t cert_base64_size, uint8_t root_cert_hash[ATCA_SHA256_DIGEST_SIZE]);
#endif
static int atecc608_get_mfr_ca_cert(const atcacert_def_t *cert_def, uint8_t *cert, size_t *cert_len);
static int atecc608_get_product_unit_cert(const atcacert_def_t *cert_def, uint8_t *cert, size_t *cert_len);
static int atecc608_get_cert_chain(cert_chain_t *cert_chain);
static int atecc608_get_digests(const cert_chain_t *cert_chain, uint8_t digest[ATCA_SHA256_DIGEST_SIZE]);
#ifdef MORE_TEST
static int mbedtls_get_cert_public_key(const cert_chain_t *cert_chain, uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE]);
static int atecc608_gen_public_key(uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE]);
#endif
static int qi_get_certificate(const cert_chain_t *cert_chain, uint8_t offset_a8, uint8_t length_a8, uint8_t offset_70, uint8_t length_70, const uint8_t **seg, uint16_t *seg_length);
#ifdef MORE_TEST
static int qi_gen_challenge_req(uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE]);
#endif
static int qi_gen_tbs_auth(const uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE], const uint8_t cert_chain_digests[ATCA_SHA256_DIGEST_SIZE], uint8_t tbs_auth_digest[ATCA_SHA256_DIGEST_SIZE]);
static int qi_challenge(const uint8_t tbs_auth_digest[ATCA_SHA256_DIGEST_SIZE], uint8_t sig[ATCA_ECCP256_SIG_SIZE]);
static int qi_test_get_digests(const cert_chain_t *cert_chain);
static int qi_test_get_certificate(const cert_chain_t *cert_chain);
#ifdef MORE_TEST
static int qi_test_challenge_auth(const uint8_t cert_chain_digest[ATCA_SHA256_DIGEST_SIZE], const uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE]);
static int qi_test_case(const cert_chain_t *cert_chain, const uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE]);
#else
static int qi_test_challenge_auth(const uint8_t cert_chain_digest[ATCA_SHA256_DIGEST_SIZE]);
static int qi_test_case(const cert_chain_t *cert_chain);
#endif

static void print_cert(const uint8_t *cert, const size_t cert_len)
{
#ifdef MORE_TEST
    uint8_t buf[1024];
    size_t buf_len = sizeof(buf);

    ESP_LOGI(TAG, "cert ->");
    ESP_LOG_BUFFER_HEXDUMP(TAG, cert, cert_len, ESP_LOG_INFO);

    atcab_base64encode(cert, cert_len, (char *)buf, &buf_len);
    buf[buf_len] = '\0';
    ESP_LOGI(TAG, "\r\n-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----", buf);
#endif
}

#ifdef MORE_TEST
static void print_config_zone(void)
{
    uint8_t buf[ATCA_ECC_CONFIG_SIZE];

    ATCA_STATUS ret = atcab_read_config_zone(buf);

    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_read_config_zone fail->0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "Config zone->");
        ESP_LOG_BUFFER_HEX(TAG, buf, ATCA_ECC_CONFIG_SIZE);
    }
}

static int test_verify_certs(void)
{
    uint8_t cert_root_ca[MAX_CERT_SIZE] = {0};
    size_t cert_root_ca_size = MAX_CERT_SIZE;
    uint8_t cert_mfr[MAX_CERT_SIZE] = {0};
    size_t cert_mfr_size = MAX_CERT_SIZE;
    uint8_t cert_product_unit[MAX_CERT_SIZE] = {0};
    size_t cert_product_unit_size = MAX_CERT_SIZE;

    int ret = atcab_base64decode(wpcca1_root_ca_base64,
                                 wpcca1_root_ca_base64_size - 1,
                                 cert_root_ca,
                                 &cert_root_ca_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcab_base64decode fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "root_cert_length -> %d", cert_root_ca_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        // ESP_LOGI(TAG, "----- root_cert -----");
        // print_cert(cert_root_ca, cert_root_ca_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }

    ret = atcacert_read_cert(&g_cert_def_1_signer, NULL, cert_mfr, &cert_mfr_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "cert_mfr_size -> %d", cert_mfr_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        // ESP_LOGI(TAG, "----- mfr_ca_cert -----");
        // print_cert(cert_mfr, cert_mfr_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }

    ret = atcacert_read_cert(&g_cert_def_2_device, NULL, cert_product_unit, &cert_product_unit_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        return 3;
    }
    else
    {
        ESP_LOGI(TAG, "product_uint_cert_len -> %d", cert_product_unit_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        // ESP_LOGI(TAG, "----- product_uint_cert -----");
        // print_cert(cert_product_unit, cert_product_unit_size);
        // ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }

    mbedtls_x509_crt chain;
    mbedtls_x509_crt ca;
    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&ca);

    ret = mbedtls_x509_crt_parse_der(&ca, cert_root_ca, cert_root_ca_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", -ret);
        return 4;
    }

    ret = mbedtls_x509_crt_parse_der(&chain, cert_root_ca, cert_root_ca_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", -ret);
        return 5;
    }

    ret = mbedtls_x509_crt_parse_der(&chain, cert_mfr, cert_mfr_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", -ret);
        return 6;
    }

    ret = mbedtls_x509_crt_parse_der(&chain, cert_product_unit, cert_product_unit_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", -ret);
        return 7;
    }

    uint32_t verified;
    ret = mbedtls_x509_crt_verify(&chain, &ca, NULL, NULL, &verified, NULL, NULL);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_verify fail-> 0x%02X", ret);
        return 8;
    }
    return 0;
}

static int atecc608_get_root_cert_hash(const char *cert_base64,
                                       size_t cert_base64_size,
                                       uint8_t root_cert_hash[ATCA_SHA256_DIGEST_SIZE])
{
    uint8_t cert[MAX_CERT_SIZE] = {0};
    size_t cert_len = sizeof(cert);

    ATCA_STATUS ret = atcab_base64decode(cert_base64, cert_base64_size, cert, &cert_len);

    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_base64decode fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "root_cert_length -> %d", cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        ESP_LOGI(TAG, "----- root_cert -----");
        print_cert(cert, cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }

    ret = atcab_hw_sha2_256(cert, cert_len, root_cert_hash);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_hw_sha2_256 fail-> 0x%02X", ret);
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "root_cert_hash ->");
        ESP_LOG_BUFFER_HEX(TAG, root_cert_hash, ATCA_SHA256_DIGEST_SIZE);
    }
    return 0;
}
#endif

static int atecc608_get_mfr_ca_cert(const atcacert_def_t *cert_def, uint8_t *cert, size_t *cert_len)
{
    int ret = atcacert_read_cert(cert_def, NULL, cert, cert_len);

    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "mfr_ca_cert_len -> %d", *cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        ESP_LOGI(TAG, "----- mfr_ca_cert -----");
        print_cert(cert, *cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }
    return 0;
}

static int atecc608_get_product_unit_cert(const atcacert_def_t *cert_def, uint8_t *cert, size_t *cert_len)
{
    int ret = atcacert_read_cert(cert_def, NULL, cert, cert_len);

    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "product_uint_cert_len -> %d", *cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        ESP_LOGI(TAG, "----- product_uint_cert -----");
        print_cert(cert, *cert_len);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }
    return 0;
}

static int atecc608_get_cert_chain(cert_chain_t *cert_chain)
{
    size_t cert_chain_buf_length = MAX_CERT_CHAIN_SIZE - sizeof(uint16_t);
#ifdef MORE_TEST
    int ret = atecc608_get_root_cert_hash(wpcca1_root_ca_base64,
                                          wpcca1_root_ca_base64_size - 1,
                                          cert_chain->cert_chain + sizeof(uint16_t));
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atecc608_get_root_cert_hash fail");
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_get_root_cert_hash pass");
        cert_chain->cert_rh_length = ATCA_SHA256_DIGEST_SIZE;
        cert_chain->cert_chain_length = sizeof(uint16_t) + cert_chain->cert_rh_length;
        *(uint16_t *)(cert_chain->cert_chain) = cert_chain->cert_chain_length;
    }
#else
    int ret = 0;
    memcpy(cert_chain->cert_chain + sizeof(uint16_t), wpcca1_root_ca_digest, ATCA_SHA256_DIGEST_SIZE);
    cert_chain->cert_rh_length = ATCA_SHA256_DIGEST_SIZE;
    cert_chain->cert_chain_length = sizeof(uint16_t) + cert_chain->cert_rh_length;
    *(uint16_t *)(cert_chain->cert_chain) = cert_chain->cert_chain_length;
#endif
    cert_chain_buf_length = MAX_CERT_CHAIN_SIZE - cert_chain->cert_chain_length;
    ret = atecc608_get_mfr_ca_cert(&g_cert_def_1_signer,
                                   cert_chain->cert_chain + sizeof(uint16_t) + cert_chain->cert_rh_length,
                                   &cert_chain_buf_length);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atecc608_get_mfr_ca_cert fail");
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_get_mfr_ca_cert pass");
        cert_chain->cert_mc_lenth = cert_chain_buf_length;
        cert_chain->cert_chain_length = sizeof(uint16_t) + cert_chain->cert_rh_length + cert_chain->cert_mc_lenth;
        *(uint16_t *)(cert_chain->cert_chain) = cert_chain->cert_chain_length;
    }

    cert_chain_buf_length = MAX_CERT_CHAIN_SIZE - cert_chain->cert_chain_length;
    ret = atecc608_get_product_unit_cert(&g_cert_def_2_device,
                                         cert_chain->cert_chain + sizeof(uint16_t) + cert_chain->cert_rh_length +
                                             cert_chain->cert_mc_lenth,
                                         &cert_chain_buf_length);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atecc608_get_product_uint_cert fail");
        return 3;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_get_product_uint_cert pass");
        cert_chain->cert_puc_length = cert_chain_buf_length;
        cert_chain->cert_chain_length = sizeof(uint16_t) +
                                        cert_chain->cert_rh_length +
                                        cert_chain->cert_mc_lenth +
                                        cert_chain->cert_puc_length;
        *(uint16_t *)(cert_chain->cert_chain) = cert_chain->cert_chain_length;
    }
    return 0;
}

static int atecc608_get_digests(const cert_chain_t *cert_chain, uint8_t digest[ATCA_SHA256_DIGEST_SIZE])
{
    ATCA_STATUS ret = atcab_hw_sha2_256(cert_chain->cert_chain,
                                        cert_chain->cert_chain_length,
                                        digest);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_hw_sha2_256 fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "cert_chain_digests ->");
        ESP_LOG_BUFFER_HEX(TAG, digest, ATCA_SHA256_DIGEST_SIZE);
    }
    return 0;
}

#ifdef MORE_TEST
static int mbedtls_get_cert_public_key(const cert_chain_t *cert_chain,
                                       uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE])
{
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    uint16_t cert_index = sizeof(uint16_t) + ATCA_SHA256_DIGEST_SIZE;
    int ret = mbedtls_x509_crt_parse_der(&cert,
                                         cert_chain->cert_chain + cert_index,
                                         *(uint16_t *)(cert_chain->cert_chain) - cert_index);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "phase manufacture ca cert pass");
    }

    cert_index += cert.raw.len;
    mbedtls_x509_crt_init(&cert);
    ret = mbedtls_x509_crt_parse_der(&cert,
                                     cert_chain->cert_chain + cert_index,
                                     *(uint16_t *)(cert_chain->cert_chain) - cert_index);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_x509_crt_parse_der fail-> 0x%02X", ret);
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "phase product unit cert pass");
    }

    size_t pk_index = cert.pk_raw.len - ATCA_ECCP256_PUBKEY_SIZE;
    memcpy(public_key, cert.pk_raw.p + pk_index, ATCA_ECCP256_PUBKEY_SIZE);

    ESP_LOGI(TAG, "cert_public_key ->");
    ESP_LOG_BUFFER_HEX(TAG, public_key, ATCA_ECCP256_PUBKEY_SIZE);

    return 0;
}

static int atecc608_gen_public_key(uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE])
{
    ATCA_STATUS ret = atcab_get_pubkey(PVKEY_SLOT_NUM, public_key);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_get_pubkey fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "gen_public_key ->");
        ESP_LOG_BUFFER_HEX(TAG, public_key, ATCA_ECCP256_PUBKEY_SIZE);
    }
    return 0;
}
#endif

static int qi_get_certificate(const cert_chain_t *cert_chain,
                              uint8_t offset_a8, uint8_t length_a8,
                              uint8_t offset_70, uint8_t length_70,
                              const uint8_t **seg, uint16_t *seg_length)
{
    size_t offset = offset_a8 * 256 + offset_70;
    size_t length = length_a8 * 256 + length_70;
    ESP_LOGI(TAG, "qi_get_certificate -> offset -> %d, length -> %d", offset, length);
    if (offset > cert_chain->cert_chain_length - 1)
    {
        ESP_LOGI(TAG, "offset exceed range.");
        return 1;
    }
    else if (length != 0 && offset + length > cert_chain->cert_chain_length)
    {
        ESP_LOGI(TAG, "offset + length exceed range.");
        return 2;
    }
    if (length == 0)
    {
        length = cert_chain->cert_chain_length - offset;
        ESP_LOGI(TAG, "qi_get_certificate -> offset -> %d, updated_length -> %d", offset, length);
    }
    *seg = cert_chain->cert_chain + offset;
    *seg_length = length;
    return 0;
}

#ifdef MORE_TEST
static int qi_gen_challenge_req(uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE])
{
    uint8_t random[RANDOM_NUM_SIZE] = {0};
    ATCA_STATUS ret = atcab_random(random);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGE(TAG, "atcab_random fail -> %d", ret);
        return 1;
    }

    challenge_req[0] = AUTH_HEADER_CHALLENGE;
    challenge_req[1] = 0x01;
    memcpy(challenge_req + 2, random, NONCE_SIZE);
    ESP_LOGI(TAG, "challenge_req ->");
    ESP_LOG_BUFFER_HEX(TAG, challenge_req, AUTH_REQ_CHALLENGE_SIZE);

    return 0;
}
#endif

static int qi_gen_tbs_auth(const uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE],
                           const uint8_t cert_chain_digests[ATCA_SHA256_DIGEST_SIZE],
                           uint8_t tbs_auth_digest[ATCA_SHA256_DIGEST_SIZE])
{
    uint8_t tbs_auth[AUTH_TBS_AUTH_SIZE] = {0};
    tbs_auth[0] = 'A';
    memcpy(tbs_auth + 1, cert_chain_digests, ATCA_SHA256_DIGEST_SIZE);
    memcpy(tbs_auth + 1 + ATCA_SHA256_DIGEST_SIZE, challenge_req, AUTH_REQ_CHALLENGE_SIZE);
    tbs_auth[1 + ATCA_SHA256_DIGEST_SIZE + AUTH_REQ_CHALLENGE_SIZE] = AUTH_HEADER_CHALLENGE_AUTH;
    tbs_auth[1 + ATCA_SHA256_DIGEST_SIZE + AUTH_REQ_CHALLENGE_SIZE + 1] = 0x11;
    tbs_auth[1 + ATCA_SHA256_DIGEST_SIZE + AUTH_REQ_CHALLENGE_SIZE + 2] = cert_chain_digests[0];
    ESP_LOGI(TAG, "tbs_auth ->");
    ESP_LOG_BUFFER_HEX(TAG, tbs_auth, AUTH_TBS_AUTH_SIZE);

    ATCA_STATUS ret = atcab_hw_sha2_256(tbs_auth, AUTH_TBS_AUTH_SIZE, tbs_auth_digest);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_hw_sha2_256 fail-> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "tbs_auth_digests ->");
        ESP_LOG_BUFFER_HEX(TAG, tbs_auth_digest, ATCA_SHA256_DIGEST_SIZE);
    }
    return 0;
}

static int qi_challenge(const uint8_t tbs_auth_digest[ATCA_SHA256_DIGEST_SIZE],
                        uint8_t sig[ATCA_ECCP256_SIG_SIZE])
{
    int ret = atcab_sign(PVKEY_SLOT_NUM, tbs_auth_digest, sig);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_sign fail-> 0x%02X", ret);
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "auth_request_sig_r ->");
        ESP_LOG_BUFFER_HEX(TAG, sig, ATCA_ECCP256_SIG_SIZE / 2);
        ESP_LOGI(TAG, "auth_request_sig_s ->");
        ESP_LOG_BUFFER_HEX(TAG, sig + ATCA_ECCP256_SIG_SIZE / 2, ATCA_ECCP256_SIG_SIZE / 2);
    }
    return 0;
}

static int qi_test_get_digests(const cert_chain_t *cert_chain)
{
    uint8_t digests_esp[ATCA_SHA256_DIGEST_SIZE] = {0};

    int ret = mbedtls_sha256_ret(cert_chain->cert_chain, cert_chain->cert_chain_length, digests_esp, false);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "mbedtls_sha256_ret fail -> 0x%02X", ret);
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "digests generated by esp32 ->");
        ESP_LOG_BUFFER_HEX(TAG, digests_esp, ATCA_SHA256_DIGEST_SIZE);
    }

    ret = memcmp(cert_chain_digests_slot0, digests_esp, ATCA_SHA256_DIGEST_SIZE);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "two digests mismatch");
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "two digests match");
    }
    return 0;
}

static int qi_test_get_certificate(const cert_chain_t *cert_chain)
{
    uint8_t offset_a8 = 0, offset_70 = sizeof(uint16_t) + ATCA_SHA256_DIGEST_SIZE;
    uint8_t length_a8 = 0, length_70 = 0;

    const uint8_t *seg;
    uint16_t seg_length;

    int ret = qi_get_certificate(cert_chain, offset_a8, length_a8, offset_70, length_70,
                                 &seg, &seg_length);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_get_certificate fail");
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "qi_get_certificate pass");

        ESP_LOGI(TAG, "cert_seg_length -> %d", seg_length);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        ESP_LOGI(TAG, "----- cert_seg -----");
        print_cert(seg, seg_length);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }
    return 0;
}

#ifdef MORE_TEST
static int qi_test_challenge_auth(const uint8_t cert_chain_digest[ATCA_SHA256_DIGEST_SIZE],
                                  const uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE])
#else
static int qi_test_challenge_auth(const uint8_t cert_chain_digest[ATCA_SHA256_DIGEST_SIZE])
#endif
{
#ifdef MORE_TEST
    uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE] = {0};
    int ret = qi_gen_challenge_req(challenge_req);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_gen_challenge_req fail");
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "qi_gen_challenge_req pass");
    }
#else
    int ret = 0;
    const uint8_t challenge_req[AUTH_REQ_CHALLENGE_SIZE] = {
        0x1b, 0x01, 0x9d, 0xc2, 0xc5, 0xcb, 0xf6, 0x52, 0x81, 0xa6, 0x01, 0x0f, 0x1c, 0x72, 0xe5, 0x8d,
        0x9e, 0x7c};
#endif

    uint8_t tbs_auth_digest[ATCA_SHA256_DIGEST_SIZE] = {0};
    ret = qi_gen_tbs_auth(challenge_req, cert_chain_digest, tbs_auth_digest);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_gen_tbs_auth fail");
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "qi_gen_tbs_auth pass");
    }

    uint8_t signature[ATCA_ECCP256_SIG_SIZE] = {0};
    ret = qi_challenge(tbs_auth_digest, signature);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_challenge fail");
        return 3;
    }
    else
    {
        ESP_LOGI(TAG, "qi_challenge pass");
    }

#ifdef MORE_TEST
    bool verified;
    ret = atcab_verify_extern(tbs_auth_digest, signature, public_key, &verified);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_verify_extern fail");
        return 4;
    }
    else if (!verified)
    {
        ESP_LOGI(TAG, "signature verify fail");
        return 5;
    }
    else
    {
        ESP_LOGI(TAG, "signature verify pass");
    }
#endif
    return 0;
}

#ifdef MORE_TEST
static int qi_test_case(const cert_chain_t *cert_chain, const uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE])
#else
static int qi_test_case(const cert_chain_t *cert_chain)
#endif
{
    ESP_LOGI(TAG, "----- qi_test_get_digest -----");
    int ret = qi_test_get_digests(cert_chain);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_test_get_digest fail");
        return 1;
    }
    else
    {
        ESP_LOGI(TAG, "qi_test_get_digest pass");
    }

    ESP_LOGI(TAG, "----- qi_test_get_certificate -----");
    ret = qi_test_get_certificate(cert_chain);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_test_get_certificate fail");
        return 2;
    }
    else
    {
        ESP_LOGI(TAG, "qi_test_get_certificate pass");
    }

    ESP_LOGI(TAG, "----- qi_test_challenge_auth -----");
#ifdef MORE_TEST
    ret = qi_test_challenge_auth(cert_chain_digests_slot0, cert_chain_slot0_public_key);
#else
    ret = qi_test_challenge_auth(cert_chain_digests_slot0);
#endif
    if (0 != ret)
    {
        ESP_LOGI(TAG, "qi_test_challenge_auth fail");
        return 3;
    }
    else
    {
        ESP_LOGI(TAG, "qi_test_challenge_auth pass");
    }
    return 0;
}
#endif

void app_main(void)
{
    const uint8_t mm[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
    ESP_LOGI(TAG, "mm ->");
    ESP_LOG_BUFFER_HEX(TAG, mm, sizeof(mm));

#ifdef BASIC_TEST
#ifdef CONFIG_ATECC608A_TNG
    // ESP_LOGI(TAG, "Initialize the ATECC interface for Trust & GO ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6A;
#elif CONFIG_ATECC608A_TFLEX   /* CONFIG_ATECC608A_TNGO */
    // ESP_LOGI(TAG, "Initialize the ATECC interface for TrustFlex ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6C;
#elif CONFIG_ATECC608A_TCUSTOM /* CONFIG_ATECC608A_TFLEX */
    // ESP_LOGI(TAG, "Initialize the ATECC interface for TrustCustom ...");
    cfg_ateccx08a_i2c_default.atcai2c.baud = 400000;
    /* Default slave address is same as that of TCUSTOM ATECC608A chips */
#endif                         /* CONFIG_ATECC608A_TCUSTOM */
    int ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_init fail -> %02x", ret);
        return;
    }
    else
    {
        ESP_LOGI(TAG, "atcab_init ok");
    }

    bool lock = 0;
    ret = atcab_is_locked(LOCK_ZONE_DATA, &lock);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_is_locked fail -> %02x", ret);
        return;
    }

    if (lock)
    {
        ESP_LOGI(TAG, "atcab_is_locked -> locked");
    }
    else
    {
        ESP_LOGE(TAG, "atcab_is_locked -> unlocked");
        return;
    }

    uint8_t buf[4];
    ret = atcab_info(buf);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_info fail -> %02x", ret);
        return;
    }
    ESP_LOGI(TAG, "device_rev ->");
    ESP_LOG_BUFFER_HEX(TAG, buf, 4);

#ifdef MORE_TEST
    print_config_zone();

    ret = test_verify_certs();
    if (0 != ret)
    {
        ESP_LOGI(TAG, "test_verify_all_certs fail -> %d", ret);
        return;
    }
    else
    {
        ESP_LOGI(TAG, "test_verify_all_certs pass");
    }
#endif

    ret = atecc608_get_cert_chain(&cert_chain_slot0);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atecc608_get_cert_chain fail");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_get_cert_chain pass");
        ESP_LOGI(TAG, "cert_chain_length -> %d", cert_chain_slot0.cert_chain_length);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
        ESP_LOGI(TAG, "----- cert_chain -----");
        print_cert(cert_chain_slot0.cert_chain, cert_chain_slot0.cert_chain_length);
        ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    }

    ret = atecc608_get_digests(&cert_chain_slot0, cert_chain_digests_slot0);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "atecc608_get_digests fail");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_get_digests pass");
    }

#ifdef MORE_TEST
    ret = mbedtls_get_cert_public_key(&cert_chain_slot0, cert_chain_slot0_public_key);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "mbedtls_get_cert_public_key fail");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "mbedtls_get_cert_public_key pass");
    }

    uint8_t gen_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    ret = atecc608_gen_public_key(gen_public_key);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "atecc608_gen_public_key fail");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "atecc608_gen_public_key pass");
    }

    ret = memcmp(cert_chain_slot0_public_key, gen_public_key, ATCA_ECCP256_PUBKEY_SIZE);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "public key generated from private key and read from cert chain mismatch");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "public key generated from private key and read from cert chain match");
    }
#endif

#ifdef MORE_TEST
    ret = qi_test_case(&cert_chain_slot0, cert_chain_slot0_public_key);
#else
    ret = qi_test_case(&cert_chain_slot0);
#endif
    if (ret != 0)
    {
        ESP_LOGI(TAG, "qi_test_case fail");
        return;
    }
    else
    {
        ESP_LOGI(TAG, "qi_test_case pass");
    }
#endif
}
