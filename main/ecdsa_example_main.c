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

/* mbedTLS includes */
#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#include "atcacert/atcacert_client.h"

#include "wpc_root_ca.h"
#include "zcust_def_1_signer.h"
#include "zcust_def_2_device.h"

static const char *TAG = "ATECC608";
/* globals for mbedtls RNG */
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static uint8_t cert_chain[1024];   // total certificate chain
static size_t cert_chain_length;   // totoal certificate length
static size_t cert_rh_length = 32; // root certificate hash length
static size_t cert_mc_lenth;       // manufacturer CA certificate length
static size_t cert_puc_length;     // product unit certificate length

static int configure_mbedtls_rng(void)
{
    int ret;
    const char *seed = "some random seed string";
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)seed, strlen(seed));
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed! mbedtls_ctr_drbg_seed returned %d", ret);
    }
    else
    {
        ESP_LOGI(TAG, "ok");
    }
    return ret;
}

static void close_mbedtls_rng(void)
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

/* An example hash */
static unsigned char hash[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static void print_cert(const uint8_t *cert, const size_t cert_len)
{
    uint8_t buf[1024];
    size_t buf_len = sizeof(buf);

    ESP_LOGI(TAG, "cert ->");
    ESP_LOG_BUFFER_HEXDUMP(TAG, cert, cert_len, ESP_LOG_INFO);

    atcab_base64encode(cert, cert_len, (char *)buf, &buf_len);
    buf[buf_len] = '\0';
    ESP_LOGI(TAG, "\r\n-----BEGIN CERTIFICATE-----\r\n%s\r\n-----END CERTIFICATE-----", buf);
}

static int atca_ecdsa_test(void)
{
    mbedtls_pk_context pkey;
    int ret;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    /* ECDSA Sign/Verify */

#ifdef MBEDTLS_ECDSA_SIGN_ALT
    /* Convert to an mbedtls key */
    ESP_LOGI(TAG, "Using a hardware private key ...");
    ret = atca_mbedtls_pk_init(&pkey, 0);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed!  atca_mbedtls_pk_init returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, "ok");
#else
    ESP_LOGI(TAG, "Generating a software private key ...");
    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_setup(&pkey,
                           mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA));
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed!  mbedtls_pk_setup returned -0x%04x", -ret);
        goto exit;
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(pkey),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed! mbedtls_ecp_gen_key returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "ok");
#endif

    ESP_LOGI(TAG, "Generating ECDSA Signature...");
    ret = mbedtls_pk_sign(&pkey, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed !mbedtls_pk_sign returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "ok");

    ESP_LOGI(TAG, "Verifying ECDSA Signature...");
    ret = mbedtls_pk_verify(&pkey, MBEDTLS_MD_SHA256, hash, 0,
                            buf, olen);
    if (ret != 0)
    {
        ESP_LOGI(TAG, "failed !mbedtls_pk_verify returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "ok");

exit:
    fflush(stdout);
    return ret;
}

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

static void print_cert_info(const atcacert_def_t *cert_def, const uint8_t *cert, size_t cert_size)
{
    uint8_t buf[256];
    int ret = atcacert_get_auth_key_id(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_auth_key_id fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "auth_key_id ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 20);
    }

    // ret = atcacert_get_cert_element();

    size_t cert_sn_size = sizeof(buf);
    ret = atcacert_get_cert_sn(cert_def, cert, cert_size, buf, &cert_sn_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_cert_sn fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "cert_sn ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, cert_sn_size);
    }

    ret = atcacert_get_comp_cert(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_comp_cert fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "comp_cert ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 72);
    }
    // ret = atcacert_get_device_data(cert_def,cert, cert_size,);

    atcacert_tm_utc_t timestamp;
    ret = atcacert_get_expire_date(cert_def, cert, cert_size, &timestamp);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_expire_date -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "expire_date -> %04d-%02d-%02d %02d:%02d:%02d",
                 timestamp.tm_year + 1900, timestamp.tm_mon + 1, timestamp.tm_mday,
                 timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec);
    }

    ret = atcacert_get_issue_date(cert_def, cert, cert_size, &timestamp);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_issue_date -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "issue_date -> %04d-%02d-%02d %02d:%02d:%02d",
                 timestamp.tm_year + 1900, timestamp.tm_mon + 1, timestamp.tm_mday,
                 timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec);
    }

    ret = atcacert_get_signature(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_signature fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "signature ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 64);
    }

    ret = atcacert_get_signer_id(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_signer_id fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "signer_id ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 2);
    }

    ret = atcacert_get_subj_key_id(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_subj_key_id fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "subj_key_id ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 20);
    }

    ret = atcacert_get_subj_public_key(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_subj_public_key fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "subj_public_key ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 64);
    }

    const uint8_t *tbs;
    size_t tbs_size;
    ret = atcacert_get_tbs(cert_def, cert, cert_size, &tbs, &tbs_size);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_tbs fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "tbs ->");
        ESP_LOG_BUFFER_HEX(TAG, tbs, tbs_size);
    }

    ret = atcacert_get_tbs_digest(cert_def, cert, cert_size, buf);
    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_get_tbs_digest fail -> 0x%02X", ret);
    }
    else
    {
        ESP_LOGI(TAG, "tbs_digest ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 32);
    }
}

void app_main(void)
{
    int ret = 0;
    bool lock;
    uint8_t buf[256];
    // uint8_t pubkey[ATCA_PUB_KEY_SIZE];

    /* Initialize the mbedtls library */
    ret = configure_mbedtls_rng();

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
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_init fail -> %02x", ret);
        goto exit;
    }
    else
    {
        ESP_LOGI(TAG, "atcab_init ok");
    }

    lock = 0;
    ret = atcab_is_locked(LOCK_ZONE_DATA, &lock);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_is_locked fail -> %02x", ret);
        goto exit;
    }

    if (lock)
    {
        ESP_LOGI(TAG, "atcab_is_locked -> locked");
    }
    else
    {
        ESP_LOGE(TAG, "atcab_is_locked -> unlocked");
        goto exit;
    }

    ret = atcab_info(buf);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_info fail -> %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, "device_rev ->");
    ESP_LOG_BUFFER_HEX(TAG, buf, 4);

    print_config_zone();

    uint8_t cert[512] = {0};
    size_t cert_len = sizeof(cert);

    ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    ESP_LOGI(TAG, "----- wpcca1_root_ca -----");
    ret = atcab_base64decode(wpcca1_root_ca_base64, wpcca1_root_ca_base64_size - 1, cert, &cert_len);

    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "atcab_base64decode fail-> 0x%02X", ret);
        goto exit;
    }
    else
    {
        ESP_LOGI(TAG, "cert_len -> %d", cert_len);
        print_cert(cert, cert_len);

        ret = calib_hw_sha2_256(atcab_get_device(), cert, cert_len, buf);
        if (ATCA_SUCCESS != ret)
        {
            ESP_LOGI(TAG, "calib_hw_sha2_256 fail-> 0x%02X", ret);
            goto exit;
        }
        else
        {
            ESP_LOGI(TAG, "SHA256 hash ->");
            ESP_LOG_BUFFER_HEX(TAG, buf, cert_rh_length);

            memcpy(cert_chain, buf, cert_rh_length);
        }
    }

    ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    ESP_LOGI(TAG, "----- g_cert_def_1_signer -----");
    cert_len = sizeof(cert);
    ret = atcacert_read_cert(&g_cert_def_1_signer, NULL, cert, &cert_len);

    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        goto exit;
    }
    else
    {
        ESP_LOGI(TAG, "cert_len -> %d", cert_len);
        cert_mc_lenth = cert_len;
        print_cert(cert, cert_mc_lenth);
        print_cert_info(&g_cert_def_1_signer, cert, cert_mc_lenth);

        memcpy(cert_chain + cert_rh_length, cert, cert_mc_lenth);
    }

    ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    ESP_LOGI(TAG, "----- g_cert_def_2_device -----");
    cert_len = sizeof(cert);
    ret = atcacert_read_cert(&g_cert_def_2_device, NULL, cert, &cert_len);

    if (0 != ret)
    {
        ESP_LOGI(TAG, "atcacert_read_cert fail-> 0x%02X", ret);
        goto exit;
    }
    else
    {
        ESP_LOGI(TAG, "cert_len -> %d", cert_len);
        cert_puc_length = cert_len;
        print_cert(cert, cert_puc_length);
        print_cert_info(&g_cert_def_2_device, cert, cert_puc_length);

        memcpy(cert_chain + cert_rh_length + cert_mc_lenth, cert, cert_puc_length);
        cert_chain_length = cert_rh_length + cert_mc_lenth + cert_puc_length;
    }

    ESP_LOGI(TAG, "----- ----- ----- ----- -----");
    ESP_LOGI(TAG, "----- cert_chain -----");

    ESP_LOGI(TAG, "cert_chain_length -> %d", cert_chain_length);
    print_cert(cert_chain, cert_chain_length);

    ret = calib_hw_sha2_256(atcab_get_device(), cert_chain, cert_chain_length, buf);
    if (ATCA_SUCCESS != ret)
    {
        ESP_LOGI(TAG, "calib_hw_sha2_256 fail-> 0x%02X", ret);
        goto exit;
    }
    else
    {
        ESP_LOGI(TAG, "SHA256 hash ->");
        ESP_LOG_BUFFER_HEX(TAG, buf, 32);
    }

    // /* Perform a Sign/Verify Test */
    // ret = atca_ecdsa_test();
    // if (ret != 0)
    // {
    //     ESP_LOGE(TAG, "ECDSA sign/verify failed");
    //     goto exit;
    // }

    // uint8_t random[32] = {0};
    // uint8_t challenge_response[64] = {0};

    // for (uint8_t ii = 0; ii < 5; ii++)
    // {
    //     ESP_LOGI(TAG, "challenge try -> %d", ii);
    //     ret = atcab_random(random);
    //     if (ATCA_SUCCESS != ret)
    //     {
    //         ESP_LOGE(TAG, "atcab_random fail -> %d", ret);
    //         break;
    //     }
    //     else
    //     {
    //         ESP_LOGI(TAG, "Random num ->");
    //         ESP_LOG_BUFFER_HEX(TAG, random, 32);
    //     }
    //     for (uint8_t slot = 0; slot <= 1; slot++)
    //     {
    //         ESP_LOGI(TAG, "slot -> %d", slot);
    //         ret = atcacert_get_response(slot, random, challenge_response);
    //         if (0 != ret)
    //         {
    //             ESP_LOGE(TAG, "atcacert_get_response fail -> %d", ret);
    //         }
    //         else
    //         {
    //             ESP_LOGI(TAG, "challenge response ->");
    //             ESP_LOG_BUFFER_HEX(TAG, challenge_response, 64);
    //         }
    //     }
    // }

exit:
    fflush(stdout);
    close_mbedtls_rng();
}
