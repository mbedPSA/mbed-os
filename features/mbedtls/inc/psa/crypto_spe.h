/**
 * \file psa/crypto_spe.h
 * \brief Platform Security Architecture cryptography module
 */

#ifndef PSA_CRYPTO_SPE_H
#define PSA_CRYPTO_SPE_H

#include "crypto.h"
#include "crypto_struct_spe.h"
#include "crypto_platform_spe.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


/** \defgroup PSA SPE Crypto declaration
 * @{
 */

/**
 * \brief Library initialization.
 *
 * Applications must call this function before calling any other
 * function in this module.
 *
 * Applications may call this function more than once. Once a call
 * succeeds, subsequent calls are guaranteed to succeed.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
*/
psa_status_t psa_sec_crypto_init(void);

/** \defgroup key_management Key management
 * @{
 */

/**
 * \brief Import a key in binary format.
 *
 * This function supports any output from psa_sec_export_key(). Refer to the
 * documentation of psa_sec_export_key() for the format for each key type.
 *
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param data        Buffer containing the key data.
 * \param data_length Size of the \c data buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported.
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval PSA_CRYPTO_ERROR_OCCUPIED_SLOT
           There is already a key in the specified slot.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_import_key(psa_key_slot_t key,
                                psa_key_type_t type,
                                const uint8_t *data,
                                size_t data_length);

/**
 * \brief Destroy a key.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_destroy_key(psa_key_slot_t key);

/**
 * \brief Get basic metadata about a key.
 *
 * \param key           Slot whose content is queried. This must
 *                      be an occupied key slot.
 * \param type          On success, the key type (a \c PSA_KEY_TYPE_XXX value).
 *                      This may be a null pointer, in which case the key type
 *                      is not written.
 * \param bits          On success, the key size in bits.
 *                      This may be a null pointer, in which case the key size
 *                      is not written.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_get_key_information(psa_key_slot_t key,
                                         psa_key_type_t *type,
                                         size_t *bits);

/**
 * \brief Export a key in binary format.
 *
 * The output of this function can be passed to psa_sec_import_key() to
 * create an equivalent object.
 *
 * If a key is created with psa_sec_import_key() and then exported with
 * this function, it is not guaranteed that the resulting data is
 * identical: the implementation may choose a different representation
 * of the same key if the format permits it.
 *
 * For standard key types, the output format is as follows:
 *
 * - For symmetric keys (including MAC keys), the format is the
 *   raw bytes of the key.
 * - For DES, the key data consists of 8 bytes. The parity bits must be
 *   correct.
 * - For Triple-DES, the format is the concatenation of the
 *   two or three DES keys.
 * - For RSA key pairs (#PSA_KEY_TYPE_RSA_KEYPAIR), the format
 *   is the non-encrypted DER representation defined by PKCS\#8 (RFC 5208)
 *   as PrivateKeyInfo.
 * - For RSA public keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY), the format
 *   is the DER representation defined by RFC 5280 as SubjectPublicKeyInfo.
 *
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_NOT_PERMITTED
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_export_key(psa_key_slot_t key,
                                uint8_t *data,
                                size_t data_size,
                                size_t *data_length);

/**
 * \brief Export a public key or the public part of a key pair in binary format.
 *
 * The output of this function can be passed to psa_sec_import_key() to
 * create an object that is equivalent to the public key.
 *
 * For standard key types, the output format is as follows:
 *
 * - For RSA keys (#PSA_KEY_TYPE_RSA_KEYPAIR or #PSA_KEY_TYPE_RSA_PUBLIC_KEY),
 *   the format is the DER representation of the public key defined by RFC 5280
 *   as SubjectPublicKeyInfo.
 * 
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_export_public_key(psa_key_slot_t key,
                                       uint8_t *data,
                                       size_t data_size,
                                       size_t *data_length);

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** The type of the key policy data structure.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_sec_key_policy_s psa_sec_key_policy_t;

/** \brief Initialize a key policy structure to a default that forbids all
 * usage of the key. */
void psa_sec_key_policy_init(psa_sec_key_policy_t *policy);

/** \brief Set the standard fields of a policy structure.
 *
 * Note that this function does not make any consistency check of the
 * parameters. The values are only checked when applying the policy to
 * a key slot with psa_sec_set_key_policy().
 */
void psa_sec_key_policy_set_usage(psa_sec_key_policy_t *policy,
                                  psa_key_usage_t usage,
                                  psa_algorithm_t alg);

psa_key_usage_t psa_sec_key_policy_get_usage(psa_sec_key_policy_t *policy);

psa_algorithm_t psa_sec_key_policy_get_algorithm(psa_sec_key_policy_t *policy);

/** \brief Set the usage policy on a key slot.
 *
 * This function must be called on an empty key slot, before importing,
 * generating or creating a key in the slot. Changing the policy of an
 * existing key is not permitted.
 *
 * Implementations may set restrictions on supported key policies
 * depending on the key type and the key slot.
 */
psa_status_t psa_sec_set_key_policy(psa_key_slot_t key,
                                    const psa_sec_key_policy_t *policy);

/** \brief Get the usage policy for a key slot.
 */
psa_status_t psa_sec_get_key_policy(psa_key_slot_t key,
                                    psa_sec_key_policy_t *policy);

/**@}*/

/** \defgroup persistence Key lifetime
 * @{
 */

/** \brief Retrieve the lifetime of a key slot.
 *
 * The assignment of lifetimes to slots is implementation-dependent.
 *
 * \param key           Slot to query.
 * \param lifetime      On success, the lifetime value.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid.
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_get_key_lifetime(psa_key_slot_t key,
                                      psa_key_lifetime_t *lifetime);

/** \brief Change the lifetime of a key slot.
 *
 * Whether the lifetime of a key slot can be changed at all, and if so
 * whether the lifetime of an occupied key slot can be changed, is
 * implementation-dependent.
 *
 * \param key           Slot whose lifetime is to be changed.
 * \param lifetime      The lifetime value to set for the given key slot.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the lifetime value is invalid.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         The implementation does not support the specified lifetime value,
 *         at least for the specified key slot.
 * \retval PSA_CRYPTO_ERROR_OCCUPIED_SLOT
 *         The slot contains a key, and the implementation does not support
 *         changing the lifetime of an occupied slot.
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_set_key_lifetime(psa_key_slot_t key,
                                      psa_key_lifetime_t lifetime);

/**@}*/

/** \defgroup hash Message digests
 * @{
 */

/** The type of the state data structure for multipart hash operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_sec_hash_operation_s psa_sec_hash_operation_t;

/** Start a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_sec_hash_start() to specify the algorithm.
 * -# Call psa_sec_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_sec_hash_finish().
 *    To compare the hash with an expected value, call psa_sec_hash_verify().
 *
 * The application may call psa_sec_hash_abort() at any time after the operation
 * has been initialized with psa_sec_hash_start().
 *
 * After a successful call to psa_sec_hash_start(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_sec_hash_update().
 * - A call to psa_sec_hash_finish(), psa_sec_hash_verify() or psa_sec_hash_abort().
 *
 * \param operation
 * \param alg       The hash algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_HASH(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a hash algorithm.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_hash_start(psa_sec_hash_operation_t *operation,
                                psa_algorithm_t alg);

/** Add a message fragment to a multipart hash operation.
 *
 * The application must call psa_sec_hash_start() before calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param operation     Active hash operation.
 * \param input         Buffer containing the message fragment to hash.
 * \param input_length  Size of the \c input buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_hash_update(psa_sec_hash_operation_t *operation,
                                 const uint8_t *input,
                                 size_t input_length);

/** Finish the calculation of the hash of a message.
 *
 * The application must call psa_sec_hash_start() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_sec_hash_update().
 *
 * When this function returns, the operation becomes inactive.
 *
 * \warning Applications should not call this function if they expect
 *          a specific value for the hash. Call psa_sec_hash_verify() instead.
 *          Beware that comparing integrity or authenticity data such as
 *          hash values with a function such as \c memcmp is risky
 *          because the time taken by the comparison may leak information
 *          about the hashed data which could allow an attacker to guess
 *          a valid hash and thereby bypass security controls.
 *
 * \param operation     Active hash operation.
 * \param hash          Buffer where the hash is to be written.
 * \param hash_size     Size of the \c hash buffer in bytes.
 * \param hash_length   On success, the number of bytes
 *                      that make up the hash value. This is always
 *                      #PSA_HASH_FINAL_SIZE(alg) where \c alg is the
 *                      hash algorithm that is calculated.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_CRYPTO_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_FINAL_SIZE(alg)
 *         where \c alg is the hash algorithm that is calculated.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_hash_finish(psa_sec_hash_operation_t *operation,
                                 uint8_t *hash,
                                 size_t hash_size,
                                 size_t *hash_length);

/** Finish the calculation of the hash of a message and compare it with
 * an expected value.
 *
 * The application must call psa_sec_hash_start() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_sec_hash_update(). It then
 * compares the calculated hash with the expected hash passed as a
 * parameter to this function.
 *
 * When this function returns, the operation becomes inactive.
 *
 * \note Implementations shall make the best effort to ensure that the
 * comparison between the actual hash and the expected hash is performed
 * in constant time.
 *
 * \param operation     Active hash operation.
 * \param hash          Buffer containing the expected hash value.
 * \param hash_length   Size of the \c hash buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the message.
 * \retval PSA_CRYPTO_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * \retval PSA_CRYPTO_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_hash_verify(psa_sec_hash_operation_t *operation,
                                 const uint8_t *hash,
                                 size_t hash_length);

/** Abort a hash operation.
 *
 * This function may be called at any time after psa_sec_hash_start().
 * Aborting an operation frees all associated resources except for the
 * \c operation structure itself.
 *
 * Implementation should strive to be robust and handle inactive hash
 * operations safely (do nothing and return #PSA_CRYPTO_ERROR_BAD_STATE). However,
 * application writers should beware that uninitialized memory may happen
 * to be indistinguishable from an active hash operation, and the behavior
 * of psa_sec_hash_abort() is undefined in this case.
 *
 * \param operation     Active hash operation.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_BAD_STATE
 *         \c operation is not an active hash operation.
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_hash_abort(psa_sec_hash_operation_t *operation);

/**@}*/

/** \defgroup MAC Message authentication codes
 * @{
 */

/** The type of the state data structure for multipart MAC operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_sec_mac_operation_s psa_sec_mac_operation_t;

/** Start a multipart MAC operation.
 *
 * The sequence of operations to calculate a MAC (message authentication code)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_sec_mac_start() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_sec_mac_update() zero, one or more times, passing a fragment
 *    of the message each time. The MAC that is calculated is the MAC
 *    of the concatenation of these messages in order.
 * -# To calculate the MAC, call psa_sec_mac_finish().
 *    To compare the MAC with an expected value, call psa_sec_mac_verify().
 *
 * The application may call psa_sec_mac_abort() at any time after the operation
 * has been initialized with psa_sec_mac_start().
 *
 * After a successful call to psa_sec_mac_start(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_sec_mac_update().
 * - A call to psa_sec_mac_finish(), psa_sec_mac_verify() or psa_sec_mac_abort().
 *
 * \param operation
 * \param alg       The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_MAC(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_NOT_PERMITTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a MAC algorithm.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_mac_start(psa_sec_mac_operation_t *operation,
                               psa_key_slot_t key,
                               psa_algorithm_t alg);

psa_status_t psa_sec_mac_update(psa_sec_mac_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length);

psa_status_t psa_sec_mac_finish(psa_sec_mac_operation_t *operation,
                                uint8_t *mac,
                                size_t mac_size,
                                size_t *mac_length);

psa_status_t psa_sec_mac_verify(psa_sec_mac_operation_t *operation,
                                const uint8_t *mac,
                                size_t mac_length);

psa_status_t psa_sec_mac_abort(psa_sec_mac_operation_t *operation);

/**@}*/

/** \defgroup cipher Symmetric ciphers
 * @{
 */

/** The type of the state data structure for multipart cipher operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_sec_cipher_operation_s psa_sec_cipher_operation_t;

/** Set the key for a multipart symmetric encryption operation.
 *
 * The sequence of operations to encrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_sec_encrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call either psa_sec_encrypt_generate_iv() or psa_sec_encrypt_set_iv() to
 *    generate or set the IV (initialization vector). You should use
 *    psa_sec_encrypt_generate_iv() unless the protocol you are implementing
 *    requires a specific IV value.
 * -# Call psa_sec_cipher_update() zero, one or more times, passing a fragment
 *    of the message each time.
 * -# Call psa_sec_cipher_finish().
 *
 * The application may call psa_sec_cipher_abort() at any time after the operation
 * has been initialized with psa_sec_encrypt_setup().
 *
 * After a successful call to psa_sec_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_sec_encrypt_generate_iv(), psa_sec_encrypt_set_iv()
 *   or psa_sec_cipher_update().
 * - A call to psa_sec_cipher_finish() or psa_sec_cipher_abort().
 *
 * \param operation
 * \param alg       The cipher algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_CIPHER(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_NOT_PERMITTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a cipher algorithm.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_encrypt_setup(psa_sec_cipher_operation_t *operation,
                                   psa_key_slot_t key,
                                   psa_algorithm_t alg);

/** Set the key for a multipart symmetric decryption operation.
 *
 * The sequence of operations to decrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_sec_decrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_cipher_update() with the IV (initialization vector) for the
 *    decryption. If the IV is prepended to the ciphertext, you can call
 *    psa_sec_cipher_update() on a buffer containing the IV followed by the
 *    beginning of the message.
 * -# Call psa_sec_cipher_update() zero, one or more times, passing a fragment
 *    of the message each time.
 * -# Call psa_sec_cipher_finish().
 *
 * The application may call psa_sec_cipher_abort() at any time after the operation
 * has been initialized with psa_sec_encrypt_setup().
 *
 * After a successful call to psa_sec_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_sec_cipher_update().
 * - A call to psa_sec_cipher_finish() or psa_sec_cipher_abort().
 *
 * \param operation
 * \param alg       The cipher algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_CIPHER(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_CRYPTO_ERROR_EMPTY_SLOT
 * \retval PSA_CRYPTO_ERROR_NOT_PERMITTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a cipher algorithm.
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_decrypt_setup(psa_sec_cipher_operation_t *operation,
                                   psa_key_slot_t key,
                                   psa_algorithm_t alg);

psa_status_t psa_sec_encrypt_generate_iv(psa_sec_cipher_operation_t *operation,
                                         unsigned char *iv,
                                         size_t iv_size,
                                         size_t *iv_length);

psa_status_t psa_sec_encrypt_set_iv(psa_sec_cipher_operation_t *operation,
                                    const unsigned char *iv,
                                    size_t iv_length);

psa_status_t psa_sec_cipher_update(psa_sec_cipher_operation_t *operation,
                                   const uint8_t *input,
                                   size_t input_length,
                                   unsigned char *output, 
                                   size_t output_size, 
                                   size_t *output_length);

psa_status_t psa_sec_cipher_finish(psa_sec_cipher_operation_t *operation,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length);

psa_status_t psa_sec_cipher_abort(psa_sec_cipher_operation_t *operation);

/**@}*/

/** \defgroup aead Authenticated encryption with associated data (AEAD)
 * @{
 */
/** Process an integrated authenticated encryption operation.
 *
 * \param operation
 * \param alg       The AEAD algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_AEAD(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not an AEAD algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_aead_encrypt( psa_key_slot_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *plaintext,
                               size_t plaintext_length,
                               uint8_t *ciphertext,
                               size_t ciphertext_size,
                               size_t *ciphertext_length );

psa_status_t psa_sec_aead_decrypt( psa_key_slot_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *ciphertext,
                               size_t ciphertext_length,
                               uint8_t *plaintext,
                               size_t plaintext_size,
                               size_t *plaintext_length );

/**@}*/

/** \defgroup asymmetric Asymmetric cryptography
 * @{
 */

/**
 * \brief Sign a hash or short message with a private key.
 *
 * \param key               Key slot containing an asymmetric key pair.
 * \param alg               A signature algorithm that is compatible with
 *                          the type of \c key.
 * \param hash              The message to sign.
 * \param hash_length       Size of the \c hash buffer in bytes.
 * \param salt              A salt or label, if supported by the signature
 *                          algorithm.
 *                          If the signature algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the signature algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param signature         Buffer where the signature is to be written.
 * \param signature_size    Size of the \c signature buffer in bytes.
 * \param signature_length  On success, the number of bytes
 *                          that make up the returned signature value.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c signature buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_sec_asymmetric_sign(psa_key_slot_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *hash,
                                     size_t hash_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *signature,
                                     size_t signature_size,
                                     size_t *signature_length);

/**
 * \brief Encrypt a short message with a public key.
 *
 * \param key               Key slot containing a public key or an asymmetric
 *                          key pair.
 * \param alg               An asymmetric encryption algorithm that is
 *                          compatible with the type of \c key.
 * \param input             The message to encrypt.
 * \param input_length      Size of the \c input buffer in bytes.
 * \param salt              A salt or label, if supported by the encryption
 *                          algorithm.
 *                          If the algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 *
 *                          - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                            supported.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param output            Buffer where the encrypted message is to be written.
 * \param output_size       Size of the \c output buffer in bytes.
 * \param output_length     On success, the number of bytes
 *                          that make up the returned output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_sec_asymmetric_encrypt(psa_key_slot_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t *input,
                                        size_t input_length, 
                                        const uint8_t *salt, 
                                        size_t salt_length,
                                        uint8_t *output,
                                        size_t output_size,
                                        size_t *output_length);

/**
 * \brief Decrypt a short message with a private key.
 *
 * \param key               Key slot containing an asymmetric key pair.
 * \param alg               An asymmetric encryption algorithm that is
 *                          compatible with the type of \c key.
 * \param input             The message to decrypt.
 * \param input_length      Size of the \c input buffer in bytes.
 * \param salt              A salt or label, if supported by the encryption
 *                          algorithm.
 *                          If the algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 *
 *                          - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                            supported.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param output            Buffer where the decrypted message is to be written.
 * \param output_size       Size of the \c output buffer in bytes.
 * \param output_length     On success, the number of bytes
 *                          that make up the returned output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_CRYPTO_ERROR_INVALID_PADDING
 */
psa_status_t psa_sec_asymmetric_decrypt(psa_key_slot_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t *input,
                                        size_t input_length,
                                        const uint8_t *salt,
                                        size_t salt_length,
                                        uint8_t *output,
                                        size_t output_size,
                                        size_t *output_length);

/**@}*/

/** \defgroup generation Key generation
 * @{
 */

/**
 * \brief Generate random bytes.
 *
 * \warning This function **can** fail! Callers MUST check the return status
 *          and MUST NOT use the content of the output buffer if the return
 *          status is not #PSA_SUCCESS.
 *
 * \note    To generate a key, use psa_sec_generate_key() instead.
 *
 * \param output            Output buffer for the generated data.
 * \param output_size       Number of bytes to generate and output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_generate_random(uint8_t *output,
                                     size_t output_size);

/**
 * \brief Generate a key or key pair.
 *
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param bits        Key size in bits.
 * \param parameters  Extra parameters for key generation. The interpretation
 *                    of this parameter depends on \c type. All types support
 *                    \c NULL to use default parameters specified below.
 *
 * For any symmetric key type (type such that
 * `PSA_KEY_TYPE_IS_ASYMMETRIC(type)` is false), \c parameters must be
 * \c NULL. For asymmetric key types defined by this specification,
 * the parameter type and the default parameters are defined by the
 * table below. For vendor-defined key types, the vendor documentation
 * shall define the parameter type and the default parameters.
 *
 * Type | Parameter type | Meaning | Parameters used if `parameters == NULL`
 * ---- | -------------- | ------- | ---------------------------------------
 * `PSA_KEY_TYPE_RSA_KEYPAIR` | `unsigned int` | Public exponent | 65537
 *
 * \retval PSA_SUCCESS
 * \retval PSA_CRYPTO_ERROR_NOT_SUPPORTED
 * \retval PSA_CRYPTO_ERROR_INVALID_ARGUMENT
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_CRYPTO_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_CRYPTO_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_CRYPTO_ERROR_HARDWARE_FAILURE
 * \retval PSA_CRYPTO_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_sec_generate_key(psa_key_slot_t key,
                                  psa_key_type_t type,
                                  size_t bits,
                                  const void *parameters);

/**@}*/

#ifdef __cplusplus
}
#endif

/* The file "crypto_struct.h" contains definitions for
 * implementation-specific structs that are declared above. */
#include "crypto_struct.h"

/* The file "crypto_extra.h" contains vendor-specific definitions. This
 * can include vendor-defined algorithms, extra functions, etc. */
#include "crypto_extra.h"

#endif /* PSA_CRYPTO_SPE_H */
