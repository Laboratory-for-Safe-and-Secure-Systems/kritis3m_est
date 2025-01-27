package kritis3mpki

/*
#cgo pkg-config: --static kritis3m_pki_client kritis3m_pki_server
#include "kritis3m_pki_server.h"
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_common.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/alogger"
)

const (
	PKCS11_LABEL_IDENTIFIER     = "pkcs11:"
	PKCS11_LABEL_IDENTIFIER_LEN = len(PKCS11_LABEL_IDENTIFIER)
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
	LogLevel          int32
	LoggingEnabled    bool
	CustomLogCallback CustomLogCallback
}

// PKCS11Module represents a PKCS#11 module configuration
type PKCS11Module struct {
	Path     string
	Slot     int
	Pin      string
	PinLen   int
	DeviceID int
}

type PKCS11Config struct {
	EntityModule PKCS11Module
	IssuerModule PKCS11Module
}

// KRITIS3MPKI represents the PKI configuration and operations
type KRITIS3MPKI struct {
	OutputCert    *C.OutputCert
	IssuerCert    *C.InputCert
	PrivateKey    *C.PrivateKey
	Error         *KRITIS3MPKIError
	Configuration *KRITIS3MPKIConfiguration
	CSR           *C.SigningRequest
	PKCS11Config  PKCS11Config
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
	return fmt.Sprintf("%s", kritis3mError)
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

var Kritis3mPKI *KRITIS3MPKI

// Create instance of PKI globally
// NewKRITIS3MPKI creates a new KRITIS3MPKI instance
func InitPKI(config *KRITIS3MPKIConfiguration) error {
	ret := C.kritis3m_pki_init(config.toC())
	if ret != C.KRITIS3M_PKI_SUCCESS {
		fmt.Println("Failed to initialize PKI")
		return nil
	}

	Kritis3mPKI = &KRITIS3MPKI{
		Configuration: config,
		Error:         &KRITIS3MPKIError{},
	}

	return nil
}

// Load PKCS#11 configuration
func (s *KRITIS3MPKI) LoadPKCS11Config(pkcs11Config PKCS11Config) {
	s.PKCS11Config = pkcs11Config
}

// LoadPrivateKey loads a private key from a PEM-encoded buffer or PKCS#11 token
func (s *KRITIS3MPKI) LoadPrivateKey(keyFile string) (keyData []byte, err error) {
	s.PrivateKey = C.privateKey_new()

	keyData, err = os.ReadFile(keyFile)
	if err == nil {
		// Check if the string starts with pkcs11:<IDENTIFIER>
		if strings.HasPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER) {
			pkcs11Identifier := strings.TrimPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER)
			logger.Infof("Referencing external key with label \"%s\"", pkcs11Identifier)

			if s.PKCS11Config.EntityModule.Path == "" || s.PKCS11Config.EntityModule.Slot == 0 {
				return nil, fmt.Errorf("PKCS#11 configuration not set")
			}

			// Initialize PKCS#11 token
			deviceID, err := s.initEntityToken(
				s.PKCS11Config.EntityModule.Path,
				s.PKCS11Config.EntityModule.Slot,
				[]byte(s.PKCS11Config.EntityModule.Pin),
				s.PKCS11Config.EntityModule.PinLen,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to initialize entity token: %v", err)
			}
			s.PKCS11Config.EntityModule.DeviceID = deviceID

			// Set external reference
			if err := s.setExternalRef(pkcs11Identifier); err != nil {
				return nil, fmt.Errorf("unable to set external reference: %v", err)
			}
		} else {
			ret := C.privateKey_loadKeyFromBuffer(s.PrivateKey, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
			if ret != C.KRITIS3M_PKI_SUCCESS {
				return nil, fmt.Errorf("PKI: failed to load private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
			}
		}
	} else {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return keyData, nil
}

// InitEntityToken initializes a PKCS#11 token for entity operations
func (s *KRITIS3MPKI) initEntityToken(modulePath string, slot int, pin []byte, pinLen int) (int, error) {
	cModulePath := C.CString(modulePath)
	defer C.free(unsafe.Pointer(cModulePath))

	var cPin *C.uint8_t
	if len(pin) > 0 {
		cPin = (*C.uint8_t)(unsafe.Pointer(&pin[0]))
	} else {
		cPin = nil
	}

	deviceID := C.kritis3m_pki_init_entity_token(
		cModulePath,
		C.int(slot),
		cPin,
		C.size_t(pinLen))

	if deviceID < C.KRITIS3M_PKI_SUCCESS {
		return 0, fmt.Errorf("failed to initialize entity token: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(C.int(deviceID))), deviceID)
	}

	return int(deviceID), nil
}

// InitIssuerToken initializes a PKCS#11 token for issuer operations
func (s *KRITIS3MPKI) initIssuerToken(modulePath string, slot uint, pin []byte, pinLen int) (int64, error) {
	cModulePath := C.CString(modulePath)
	defer C.free(unsafe.Pointer(cModulePath))

	deviceID := C.kritis3m_pki_init_issuer_token(
		cModulePath,
		C.int(slot),
		(*C.uint8_t)(unsafe.Pointer(&pin[0])),
		C.size_t(pinLen))

	if deviceID < C.KRITIS3M_PKI_SUCCESS {
		return 0, fmt.Errorf("failed to initialize issuer token: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(C.int(deviceID))), deviceID)
	}

	return int64(deviceID), nil
}

// SetExternalRef sets an external reference for PKCS#11 key
func (s *KRITIS3MPKI) setExternalRef(label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	ret := C.privateKey_setExternalRef(s.PrivateKey, C.int(s.PKCS11Config.EntityModule.DeviceID), cLabel)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to set external reference: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(ret)), ret)
	}
	return nil
}

// LoadPrivateKeyAlt loads an alternative private key
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
		C.inputCert_free(s.IssuerCert)
	}
	if s.PrivateKey != nil {
		C.privateKey_free(s.PrivateKey)
	}
	if s.CSR != nil {
		C.signingRequest_free(s.CSR)
	}
	// Close PKCS#11 tokens
	C.kritis3m_pki_close_entity_token()
	C.kritis3m_pki_close_issuer_token()
}
