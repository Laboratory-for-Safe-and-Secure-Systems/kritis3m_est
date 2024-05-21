#ifndef KRITIS3M_PKI_SERVER_H
#define KRITIS3M_PKI_SERVER_H

#include <stdint.h>
#include <stdbool.h>

#include "kritis3m_pki_common.h"


/* Forward declarations of our data types.
 * The actual declarations are in the source file to hide
 * the internal dependencies. */
typedef struct issuerCert IssuerCert;
typedef struct outputCert OutputCert;


/* Create a new IssuerCert object. */
IssuerCert* issuerCert_new(void);


/* Initialize the given IssuerCert `cert` using the PEM encoded data in the provided `buffer`
 * with `buffer_size` bytes.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int issuerCert_initFromBuffer(IssuerCert* cert, uint8_t const* buffer, size_t buffer_size);


/* Free the memory of given IssuerCert */
void issuerCert_free(IssuerCert* cert);


/* Create a new OutputCert object. */
OutputCert* outputCert_new(void);


/* Initialize the given OutputCert from the CSR, PEM encoded in the provided `bufffer` with
 * `buffer_size` bytes.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_initFromCsr(OutputCert* outputCert, uint8_t const* buffer, size_t buffer_size);


/* Set issuer data of the new OutputCert `outputCert` using data from IssuerCert `issuerCert`
 * and issuer private key `issuerKey`.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_setIssuerData(OutputCert* outputCert, IssuerCert* issuerCert, PrivateKey* issuerKey);


/* Set the validity period to `days` days of the new OutputCert `outputCert`.
 */
void outputCert_setValidity(OutputCert* outputCert, int days);


/* Configure the new OutputCert to be a CA certificate, capable of signing new certificates.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_configureAsCA(OutputCert* outputCert);


/* Configure the new OutputCert to be an entity certificate for authentication.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_configureAsEntity(OutputCert* outputCert);


/* Finalize the new OutputCert by signing it with the issuer private key. Store the final PEM
 * encoded output in the buffer `buffer`. On function entry, `buffer_size` must contain the
 * size of the provided output buffer. After successful completion, `buffer_size` will contain
 * the size of the written output in the buffer.
 *
 * Return value is `KRITIS3M_PKI_SUCCESS` in case of success, negative error code otherwise.
 */
int outputCert_finalize(OutputCert* outputCert, PrivateKey* issuerKey, uint8_t* buffer, size_t* buffer_size);


/* Free the memory of given OutputCert */
void outputCert_free(OutputCert* outputCert);


#endif /* KRITIS3M_PKI_SERVER_H */
