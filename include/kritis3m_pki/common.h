#ifndef KRITIS3M_PKI_COMMON_H
#define KRITIS3M_PKI_COMMON_H


#include <stdint.h>
#include <stdbool.h>

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/falcon.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/error-crypt.h"


#define LARGE_TEMP_SZ 12288
#define TEMP_SZ 256

#define SubjectAltPublicKeyInfoExtension "2.5.29.72"
#define AltSignatureAlgorithmExtension "2.5.29.73"
#define AltSignatureValueExtension "2.5.29.74"


typedef struct privateKey
{
        uint8_t buffer[LARGE_TEMP_SZ];
        size_t size;
        int type;
        int certKeyType;
        bool init;
        union
        {
                ecc_key ecc;
                RsaKey rsa;
                dilithium_key dilithium;
                falcon_key falcon;
        }
        key;
}
PrivateKey;

typedef struct issuerCert
{
        bool init;
        uint8_t buffer[LARGE_TEMP_SZ];
        size_t size;
}
IssuerCert;

typedef struct altKeyData
{
        int sigAlgOID;
        uint8_t pubKeyBuffer[LARGE_TEMP_SZ];
        size_t pubKeySize;

        uint8_t sigAlgBuffer[TEMP_SZ];
        size_t sigAlgSize;

        uint8_t sigBuffer[LARGE_TEMP_SZ];
        size_t sigSize;
}
AltKeyData;

typedef struct outputCert
{
        Cert cert;
        DecodedCert preTbs;
        bool preTbsInit;

        uint8_t buffer1[LARGE_TEMP_SZ];
        size_t size1;

        uint8_t buffer2[LARGE_TEMP_SZ];
        size_t size2;

}
OutputCert;


int readFile(const char* filePath, uint8_t* buffer, size_t* bufferSize);
int writeFile(const char* filePath, uint8_t* buffer, size_t bufferSize);
int decodeKey(uint8_t* buffer, size_t* buffer_size, int* key_type);

int loadPrivateKey(const char* filePath, PrivateKey* key);
int loadIssuerCert(const char* filePath, IssuerCert* cert);

void freePrivateKey(PrivateKey* key);
void freeOutputCert(OutputCert* outputCert);

int storeOutputCert(const char* filePath, OutputCert* outputCert);

int genAltCertInfo(AltKeyData* altKeyData, PrivateKey* issuerAltKey, PrivateKey* ownAltKey);

int prepareOutputCert(OutputCert* outputCert, PrivateKey* issuerKey, AltKeyData* altKeyData);

int finalizeOutputCert(OutputCert* outputCert, PrivateKey* issuerKey,
                       PrivateKey* issuerAltKey, PrivateKey* ownKey,
                       AltKeyData* altKeyData);

#endif /* KRITIS3M_PKI_COMMON_H */
