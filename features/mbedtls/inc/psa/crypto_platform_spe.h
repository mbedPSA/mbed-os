/**
 * \file psa/crypto_platform_spe.h
 *
 * \brief PSA cryptography module: Mbed TLS platfom definitions
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_SPE_PLATFORM_H
#define PSA_CRYPTO_SPE_PLATFORM_H

#include "spm/psa_defs.h"
#include "spm/spm_client.h"

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "../mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/** \defgroup PSA Crypto APIs
* @{
*/

/** \brief psa_s_function_t enum defines for all the available functions in PSA Crypto. */
typedef enum psa_sec_function_s
{
    PSA_CRYPTO_INVALID,
    PSA_CRYPTO_INIT,
    PSA_IMPORT_KEY,
    PSA_DESTROY_KEY,
    PSA_GET_KEY_INFORMATION,
    PSA_EXPORT_KEY,
    PSA_EXPORT_PUBLIC_KEY,
    PSA_KEY_POLICY_INIT,
    PSA_KEY_POLICY_SET_USAGE,
    PSA_KEY_POLICY_GET_USAGE,
    PSA_KEY_POLICY_GET_ALGORITHM,
    PSA_SET_KEY_POLICY,
    PSA_GET_KEY_POLICY,
    PSA_SET_KEY_LIFETIME,
    PSA_GET_KEY_LIFETIME,
    PSA_HASH_START,
    PSA_HASH_UPDATE,
    PSA_HASH_FINISH,
    PSA_HASH_VERIFY,
    PSA_HASH_ABORT,
    PSA_MAC_START,
    PSA_MAC_UPDATE,
    PSA_MAC_FINISH,
    PSA_MAC_VERIFY,
    PSA_MAC_ABORT,
    PSA_ENCRYPT_SETUP,
    PSA_DECRYPT_SETUP,
    PSA_ENCRYPT_GENERATE_IV,
    PSA_ENCRYPT_SET_IV,
    PSA_CIPHER_UPDATE,
    PSA_CIPHER_FINISH,
    PSA_CIPHER_ABORT,
    PSA_AEAD_ENCRYPT,
    PSA_AEAD_DECRYPT,
    PSA_ASYMMETRIC_SIGN,
    PSA_ASYMMETRIC_VERIFY,
    PSA_ASYMMETRIC_ENCRYPT,
    PSA_ASYMMETRIC_DECRYPT,
    PSA_GENERATE_RANDOM,
    PSA_GENERATE_KEY
}psa_sec_function_t;

/**@}*/

/** \defgroup PSA Crypto structures for IPC
* @{
*/

/** psa_crypto_ipc_s struct used for some of the 
 * PSA Crypto APIs that need psa_key_slot_t and psa_algorithm_t arguments
 * and in order to use the existing infrastructure of the SPM-IPC we provide a struct to 
 * pack them together.
 */

typedef struct psa_crypto_ipc_s
{
    psa_sec_function_t func;
    psa_key_slot_t key;
    psa_algorithm_t alg;
} psa_crypto_ipc_t;

/** psa_key_mng_ipc_s struct used for some of the 
 * PSA Crypto APIs that need psa_key_slot_t and psa_algorithm_t arguments
 * and in order to use the existing infrastructure of the SPM-IPC we provide a struct to 
 * pack them together.
 */

typedef struct psa_key_mng_ipc_s
{
    psa_key_slot_t key;
    psa_key_type_t type;
    psa_sec_function_t func;
} psa_key_mng_ipc_t;

/** psa_crypto_ipc_aead_s struct used for AEAD integrated 
 * PSA Crypto APIs that need psa_key_slot_t and psa_algorithm_t  and extra arguments
 * and in order to use the existing infrastructure of the SPM-IPC we provide a struct to 
 * pack them together.
 */
#define MAX_NONCE_SIZE 16
typedef struct psa_crypto_ipc_aead_s
{
    psa_sec_function_t func;
    psa_key_slot_t key;
    psa_algorithm_t alg;
    size_t nonce_size;
    uint8_t nonce[MAX_NONCE_SIZE];
} psa_crypto_ipc_aead_t;

/** psa_crypto_ipc_asymmetric_s struct used for asymmetric 
 * PSA Crypto APIs that need psa_key_slot_t and psa_algorithm_t arguments
 * and in order to use the existing infrastructure of the SPM-IPC we provide a struct to 
 * pack them together.
 */
#define PSA_SIGNATURE_MAX_SIZE 72
typedef struct psa_crypto_ipc_asymmetric_s
{
    psa_sec_function_t func;
    psa_key_slot_t key;
    psa_algorithm_t alg;
    size_t output_size;
    size_t signature_size;
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE];
}psa_crypto_ipc_asymmetric_t;


/**@}*/

#endif /* PSA_CRYPTO_SPE_PLATFORM_H */
