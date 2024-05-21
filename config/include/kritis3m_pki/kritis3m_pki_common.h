#ifndef KRITIS3M_PKI_COMMON_H
#define KRITIS3M_PKI_COMMON_H


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct privateKey PrivateKey;


/* Error Codes */
enum KRITIS3M_PKI_Erros {
        KRITIS3M_PKI_SUCCESS = 0,
        KRITIS3M_PKI_MEMORY_ERROR = -1,
        KRITIS3M_PKI_PEM_DECODE_ERROR = -2,
        KRITIS3M_PKI_PEM_ENCODE_ERROR = -3,
        KRITIS3M_PKI_KEY_ERROR = -4,
        KRITIS3M_PKI_KEY_UNSUPPORTED = -5,
        KRITIS3M_PKI_CSR_ERROR = -6,
        KRITIS3M_PKI_CSR_EXT_ERROR = -7,
        KRITIS3M_PKI_CSR_SIGN_ERROR = -8,
        KRITIS3M_PKI_CERT_ERROR = -9,
        KRITIS3M_PKI_CERT_EXT_ERROR = -10,
        KRITIS3M_PKI_CERT_SIGN_ERROR = -11,
};


/* Create a new PrivateKey object */
PrivateKey* privateKey_new(void);


/* Initialize the given PrivateKey `key` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes. The key type is determined automatically. When the PEM file
 * contains both a primary and an alternative key, both are loaded. Otherwise, an alternative
 * key could be loaded from a separate buffer using `loadAltPrivateKeyFromPemBuffer()` if
 * required.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);


/* Load an alternative private key from the PEM encoded data in the provided `buffer` with
 * `buffer_size` bytes and store it decoded in the `key` PrivateKey object.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int privateKey_loadAltKeyFromBuffer(PrivateKey* key, uint8_t const* buffer, size_t buffer_size);


/* Free the memory of given PrivateKey */
void privateKey_free(PrivateKey* key);


#endif /* KRITIS3M_PKI_COMMON_H */
