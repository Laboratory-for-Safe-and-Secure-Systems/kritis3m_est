package kritis3mpki

/*
#cgo pkg-config: --static kritis3m_pki_client
#include "kritis3m_pki_server.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_common.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/est/internal/alogger"
)

var logger = alogger.New(os.Stderr)

// KRITIS3MPKIError represents a PKI error
type KRITIS3MPKIError struct {
	Code    int
	Message string
}

type CustomLogCallback C.kritis3m_pki_log_callback

// KRITIS3MPKIConfiguration represents the PKI configuration
type KRITIS3MPKIConfiguration struct {
	LogLevel          int
	LoggingEnabled    bool
	CustomLogCallback CustomLogCallback
}

// KRITIS3MPKI represents the PKI configuration and operations
type KRITIS3MPKI struct {
	OutputCert    *C.OutputCert
	IssuerCert    *C.IssuerCert
	PrivateKey    *C.PrivateKey
	Error         *KRITIS3MPKIError
	Configuration *KRITIS3MPKIConfiguration
	CSR           *C.SigningRequest
}

func (pc *KRITIS3MPKIConfiguration) toC() *C.kritis3m_pki_configuration {
	return &C.kritis3m_pki_configuration{
		log_level:       C.int(pc.LogLevel),
		logging_enabled: C.bool(pc.LoggingEnabled),
		log_callback:    (C.kritis3m_pki_log_callback)(pc.CustomLogCallback),
	}
}

// KRITIS3MPKIError returns the error message for the given error code
func (e *KRITIS3MPKIError) Error() string {
	kritis3mError := C.GoString(C.kritis3m_pki_error_message(C.int(e.Code)))
	logger.Debugf("Error code: %d, Error message: %s", e.Code, kritis3mError)
	return fmt.Sprintf(kritis3mError)
}

const (
	KRITIS3M_PKI_SUCCESS          = C.KRITIS3M_PKI_SUCCESS
	KRITIS3M_PKI_MEMORY_ERROR     = C.KRITIS3M_PKI_MEMORY_ERROR
	KRITIS3M_PKI_ARGUMENT_ERROR   = C.KRITIS3M_PKI_ARGUMENT_ERROR
	KRITIS3M_PKI_PEM_DECODE_ERROR = C.KRITIS3M_PKI_PEM_DECODE_ERROR
	KRITIS3M_PKI_PEM_ENCODE_ERROR = C.KRITIS3M_PKI_PEM_ENCODE_ERROR
	KRITIS3M_PKI_KEY_ERROR        = C.KRITIS3M_PKI_KEY_ERROR
	KRITIS3M_PKI_KEY_UNSUPPORTED  = C.KRITIS3M_PKI_KEY_UNSUPPORTED
	KRITIS3M_PKI_CSR_ERROR        = C.KRITIS3M_PKI_CSR_ERROR
	KRITIS3M_PKI_CSR_EXT_ERROR    = C.KRITIS3M_PKI_CSR_EXT_ERROR
	KRITIS3M_PKI_CSR_SIGN_ERROR   = C.KRITIS3M_PKI_CSR_SIGN_ERROR
	KRITIS3M_PKI_CERT_ERROR       = C.KRITIS3M_PKI_CERT_ERROR
	KRITIS3M_PKI_CERT_EXT_ERROR   = C.KRITIS3M_PKI_CERT_EXT_ERROR
	KRITIS3M_PKI_CERT_SIGN_ERROR  = C.KRITIS3M_PKI_CERT_SIGN_ERROR
	KRITIS3M_PKI_PKCS11_ERROR     = C.KRITIS3M_PKI_PKCS11_ERROR
)

const (
	KRITIS3M_PKI_LOG_LEVEL_ERR = C.KRITIS3M_PKI_LOG_LEVEL_ERR
	KRITIS3M_PKI_LOG_LEVEL_WRN = C.KRITIS3M_PKI_LOG_LEVEL_WRN
	KRITIS3M_PKI_LOG_LEVEL_INF = C.KRITIS3M_PKI_LOG_LEVEL_INF
	KRITIS3M_PKI_LOG_LEVEL_DBG = C.KRITIS3M_PKI_LOG_LEVEL_DBG
)

type Algorithm string

const (
	ALGORITHMRSA2048 Algorithm = "rsa2048"
	ALGORITHMRSA3072 Algorithm = "rsa3072"
	ALGORITHMRSA4096 Algorithm = "rsa4096"
	ALGORITHMSECP256 Algorithm = "secp256"
	ALGORITHMSECP384 Algorithm = "secp384"
	ALGORITHMSECP521 Algorithm = "secp521"
	ALGORITHMED25519 Algorithm = "ed25519"
	ALGORITHMED448   Algorithm = "ed448"
	ALGORITHMMLDSA44 Algorithm = "mldsa44"
	ALGORITHMMLDSA65 Algorithm = "mldsa65"
	ALGORITHMMLDSA87 Algorithm = "mldsa87"
)

// NewKRITIS3MPKI creates a new KRITIS3MPKI instance
func InitPKI(config *KRITIS3MPKIConfiguration) *KRITIS3MPKI {
	ret := C.kritis3m_pki_init(config.toC())
	if ret != C.KRITIS3M_PKI_SUCCESS {
		fmt.Println("Failed to initialize PKI")
		return nil
	}

	return &KRITIS3MPKI{
		Configuration: config,
		Error:         &KRITIS3MPKIError{},
	}
}

// LoadPrivateKey loads a private key from a PEM-encoded buffer
func (s *KRITIS3MPKI) LoadPrivateKey(keyData []byte) error {
	s.PrivateKey = C.privateKey_new()
	// Check if keyDATA starts with pkcs11:
	if len(keyData) > 7 && string(keyData[:7]) != "pkcs11:" {
		ret := C.privateKey_loadKeyFromBuffer(s.PrivateKey, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
		if ret != C.KRITIS3M_PKI_SUCCESS {
			return fmt.Errorf("PKI: failed to load private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
		}
	}
	return nil
}

// LoadPrivateKeyAlt loads an alternative private key from a PEM-encoded buffer
func (s *KRITIS3MPKI) LoadPrivateKeyAlt(keyData []byte) error {
	if s.PrivateKey == nil {
		return fmt.Errorf("primary private key must be loaded first")
	}
	ret := C.privateKey_loadAltKeyFromBuffer(s.PrivateKey, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to load alternative private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

// GeneratePrivateKey generates a new private key
func (s *KRITIS3MPKI) GeneratePrivateKey(algorithm Algorithm) error {
	s.PrivateKey = C.privateKey_new()
	cAlgorithm := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(cAlgorithm))
	s.Error.Code = int(C.privateKey_generateKey(s.PrivateKey, cAlgorithm))
	if s.Error.Code != KRITIS3M_PKI_SUCCESS {
		return s.Error
	}
	return nil
}

// GeneratePrivateKeyAlt generates a new alternative private key
func (s *KRITIS3MPKI) GeneratePrivateKeyAlt(algorithm Algorithm) error {
	if s.PrivateKey == nil {
		return fmt.Errorf("primary private key must be generated first")
	}
	cAlgorithm := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(cAlgorithm))
	s.Error.Code = int(C.privateKey_generateAltKey(s.PrivateKey, cAlgorithm))
	if s.Error.Code != KRITIS3M_PKI_SUCCESS {
		return s.Error
	}
	return nil
}

// Cleanup frees all allocated resources
func (s *KRITIS3MPKI) Cleanup() {
	if s.OutputCert != nil {
		C.outputCert_free(s.OutputCert)
	}
	if s.IssuerCert != nil {
		C.issuerCert_free(s.IssuerCert)
	}
	if s.PrivateKey != nil {
		C.privateKey_free(s.PrivateKey)
	}
	if s.CSR != nil {
		C.signingRequest_free(s.CSR)
	}
}
