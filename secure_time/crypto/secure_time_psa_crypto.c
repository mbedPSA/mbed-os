/* Copyright (c) 2018 ARM Limited
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

#include "secure_time_crypto.h"
#include "secure_time_client_spe.h"
#include "mbed_error.h"

#include "crypto.h"

#if !defined(PSA_GENERATE_RANDOM)

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/*
 * Structure containing contexts for random number generation.
 */
typedef struct secure_time_random_ctx {
    mbedtls_ctr_drbg_context ctr_drbg_ctx; /* CTR_DRBG context structure. */
    mbedtls_entropy_context entropy_ctx;   /* Entropy context structure. */
} secure_time_random_ctx_t;

static void random_ctx_init(secure_time_random_ctx_t *ctx)
{
    int rc = SECURE_TIME_SUCCESS;

    mbedtls_entropy_init(&(ctx->entropy_ctx));
    mbedtls_ctr_drbg_init(&(ctx->ctr_drbg_ctx));
    rc = mbedtls_ctr_drbg_seed(
        &(ctx->ctr_drbg_ctx),
        mbedtls_entropy_func,
        &(ctx->entropy_ctx),
        0,
        0
        );
    if (SECURE_TIME_SUCCESS != rc) {
        error("mbedtls_ctr_drbg_seed() failed! (rc=%d)", rc);
    }
}

static void random_ctx_free(secure_time_random_ctx_t *ctx)
{
    mbedtls_entropy_free(&(ctx->entropy_ctx));
    mbedtls_ctr_drbg_free(&(ctx->ctr_drbg_ctx));
}

#endif // !defined(PSA_GENERATE_RANDOM)

static psa_algorithm_t psa_hash_alg_from_signature_alg(SignatureAlg alg)
{
    switch(alg) {
        case SIGNATURE_ALG_SHA256_ECDSA:
            return PSA_ALG_SHA_256;
        default:
            return PSA_ALG_HASH_MASK;
    }
}

static psa_key_type_t psa_key_type_from_signature_alg(SignatureAlg alg)
{
    switch(alg) {
        case SIGNATURE_ALG_SHA256_ECDSA:
            return PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_KEY_TYPE_ECC_CURVE_NISTP256R1);
        default:
            return PSA_KEY_TYPE_NONE;
    }
}

static void calculate_hash(
    const void *data,
    size_t data_size,
    psa_algorithm_t hash_alg,
    uint8_t *hash,
    size_t hash_size
    )
{
    int rc = SECURE_TIME_SUCCESS;
    psa_algorithm_t alg = hash_alg;
    psa_hash_operation_t operation = {0};
    size_t actual_hash_length = 0;

    rc = psa_crypto_init();
    if (PSA_SUCCESS != rc) {
        error("psa_crypto_init() failed! (rc=%d)", rc);
    }

    rc = psa_hash_start(&operation, alg);
    if (PSA_SUCCESS != rc) {
        error("psa_hash_start() failed! (rc=%d)", rc);
    }

    rc = psa_hash_update(&operation, data, data_size);
    if (PSA_SUCCESS != rc) {
        error("psa_hash_update() failed! (rc=%d)", rc);
    }

    rc = psa_hash_finish(&operation, hash, hash_size, &actual_hash_length);
    if (PSA_SUCCESS != rc) {
        error("psa_hash_finish() failed! (rc=%d)", rc);
    }
}

int32_t secure_time_verify_signature(
    const void *data,
    size_t data_size,
    const void *sign,
    size_t sign_size,
    const void *pubkey,
    size_t pubkey_size
    )
{
    int rc = SECURE_TIME_SUCCESS;

    psa_algorithm_t hash_alg = psa_hash_alg_from_signature_alg(SIGNATURE_ALG_SHA256_ECDSA);
    psa_key_type_t key_type = psa_key_type_from_signature_alg(SIGNATURE_ALG_SHA256_ECDSA);
    if ((PSA_ALG_HASH_MASK == hash_alg) || (PSA_KEY_TYPE_NONE == key_type)) {
        error("Failed to determine the signature algorithm!");
    }

    uint8_t hash[PSA_HASH_FINAL_SIZE(PSA_ALG_SHA_256)] = {0};

    calculate_hash(data, data_size, hash_alg, hash, sizeof(hash));

    psa_key_policy_t policy = {0};
    int slot = 1; // TODO: How to get valid slot?

    psa_key_policy_init(&policy);
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, hash_alg);

    rc = psa_set_key_policy(1, &policy);
    if (PSA_SUCCESS != rc) {
        error("psa_set_key_policy() failed! (rc=%d)", rc);
    }

    rc = psa_import_key(slot, key_type, pubkey, pubkey_size);
    if (PSA_SUCCESS != rc) {
        error("psa_import_key() failed! (rc=%d)", rc);
    }

    rc = psa_asymmetric_verify(
        slot,
        hash_alg,
        hash,
        sizeof(hash),
        NULL,
        0,
        (uint8_t *)sign,
        sign_size
        );
    if (PSA_SUCCESS != rc) {
        rc = SECURE_TIME_SIGNATURE_VERIFICATION_FAILED;
    }

    int rc1 = psa_destroy_key(slot);
    if (PSA_SUCCESS != rc1) {
        error("psa_destroy_key() failed! (rc=%d)", rc1);
    }

    return rc;
}

void secure_time_generate_random_bytes(size_t size, void *random_buf)
{
#if !defined(PSA_GENERATE_RANDOM)
    int rc = SECURE_TIME_SUCCESS;
    secure_time_random_ctx_t *random_ctx =
        (secure_time_random_ctx_t *)malloc(sizeof(*random_ctx));

    if (NULL == random_ctx) {
        error("Failed to allocate memory for random_ctx!");
    }

    random_ctx_init(random_ctx);
    rc = mbedtls_ctr_drbg_random(&(random_ctx->ctr_drbg_ctx), (unsigned char *)random_buf, size);
    if (SECURE_TIME_SUCCESS != rc) {
        error("mbedtls_ctr_drbg_random() failed! (rc=%d)", rc);
    }

    random_ctx_free(random_ctx);
    free(random_ctx);
#else
    int rc = psa_generate_random((uint8_t *)random_buf, size);
    if (PSA_SUCCESS != rc) {
        error("psa_generate_random() failed! (rc=%d)", rc);
    }
#endif
}
