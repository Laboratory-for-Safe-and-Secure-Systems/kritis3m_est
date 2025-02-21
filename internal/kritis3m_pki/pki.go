package kritis3m_pki

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
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
	"github.com/rs/zerolog"
)

const (
	PKCS11_LABEL_IDENTIFIER     = "pkcs11:"
	PKCS11_LABEL_IDENTIFIER_LEN = len(PKCS11_LABEL_IDENTIFIER)
	PKCS11_LABEL_TERMINATOR     = "\r\n"
)

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
	DeviceID int
}

type PKCS11Config struct {
	EntityModule *PKCS11Module
	IssuerModule *PKCS11Module
}

// KRITIS3MPKI represents the PKI configuration and operations
type KRITIS3MPKI struct {
	OutputCert    *C.OutputCert
	IssuerCert    *C.InputCert
	IssuerKey     *C.PrivateKey
	EntityKey     *C.PrivateKey
	Error         *KRITIS3MPKIError
	Configuration *KRITIS3MPKIConfiguration
	CSR           *C.SigningRequest
	PKCS11        PKCS11Config
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
	return kritis3mError
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

var logger est.Logger
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

	logLevel := zerolog.WarnLevel

	switch config.LogLevel {
	case KRITIS3M_PKI_LOG_LEVEL_ERR:
		logLevel = zerolog.ErrorLevel
	case KRITIS3M_PKI_LOG_LEVEL_WRN:
		logLevel = zerolog.WarnLevel
	case KRITIS3M_PKI_LOG_LEVEL_INF:
		logLevel = zerolog.InfoLevel
	case KRITIS3M_PKI_LOG_LEVEL_DBG:
		logLevel = zerolog.DebugLevel
	}
	logger = alogger.New(os.Stderr, logLevel)

	return nil
}

// Load PKCS#11 configuration
func (s *KRITIS3MPKI) LoadPKCS11Config(pkcs11Config PKCS11Config) {
	s.PKCS11 = pkcs11Config
}

// Function to extract the key label and a potential alt key label
func extractKeyLabel(keyData []byte) (string, string) {
	keyLabel := ""
	altKeyLabel := ""

	// Check if the string starts with pkcs11:<IDENTIFIER>
	if strings.HasPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER) {
		labelFull := strings.TrimPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER)
		keyLabel = labelFull
		idx := strings.Index(labelFull, PKCS11_LABEL_TERMINATOR)
		if idx != -1 {
			keyLabel = labelFull[:idx]
			labelFull = labelFull[idx:]
			labelFull = strings.TrimPrefix(labelFull, PKCS11_LABEL_TERMINATOR)
		}

		// Check if an additional label for an alternative key is provided
		if len(labelFull) > 0 && strings.HasPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER) {
			altKeyLabel = strings.TrimPrefix(labelFull, PKCS11_LABEL_IDENTIFIER)
			altKeyLabel = strings.TrimSuffix(altKeyLabel, PKCS11_LABEL_TERMINATOR)
		}
	}

	return keyLabel, altKeyLabel
}

// LoadPrivateKey loads a private key from a PEM-encoded buffer or PKCS#11 token
func (s *KRITIS3MPKI) LoadPrivateKey(keyFile string, p11_module *PKCS11Module) (keyData []byte, key *C.PrivateKey, err error) {
	key = C.privateKey_new()

	keyData, err = os.ReadFile(keyFile)
	if err == nil {
		// Check if the string starts with pkcs11:<IDENTIFIER>
		if strings.HasPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER) {
			keyLabel, altKeyLabel := extractKeyLabel(keyData)

			logger.Infof("Referencing external key with label \"%s\"", keyLabel)

			if p11_module == nil || p11_module.Path == "" {
				return nil, nil, fmt.Errorf("PKCS#11 configuration not set")
			}

			// Initialize PKCS#11 token
			deviceID, err := s.InitPkcs11Token(p11_module)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to initialize PKCS11 token: %v", err)
			}
			p11_module.DeviceID = deviceID

			// Set external reference
			if err := s.setExternalRef(keyLabel, key, p11_module); err != nil {
				return nil, nil, fmt.Errorf("unable to set external reference: %v", err)
			}

			// Check if an additional label for an alternative key is provided
			if len(altKeyLabel) > 0 {
				logger.Infof("Referencing alternative key with label \"%s\"", altKeyLabel)

				// Set external reference for alternative key
				if err := s.setAltExternalRef(altKeyLabel, key, p11_module); err != nil {
					return nil, nil, fmt.Errorf("unable to set external reference for alternative key: %v", err)
				}
			}
		} else {
			ret := C.privateKey_loadKeyFromBuffer(key, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
			if ret != C.KRITIS3M_PKI_SUCCESS {
				return nil, nil, fmt.Errorf("PKI: failed to load private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
			}
		}
	} else {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return keyData, key, nil
}

// LoadPrivateKeyAlt loads an alternative private key
func (s *KRITIS3MPKI) LoadPrivateKeyAlt(keyFile string, key *C.PrivateKey, p11_module *PKCS11Module) error {
	if key == nil {
		return fmt.Errorf("primary private key must be loaded first")
	}

	keyData, err := os.ReadFile(keyFile)
	if err == nil {
		// Check if the string starts with pkcs11:<IDENTIFIER>
		if strings.HasPrefix(string(keyData), PKCS11_LABEL_IDENTIFIER) {
			keyLabel, altKeyLabel := extractKeyLabel(keyData)

			logger.Infof("Referencing external key with label \"%s\"", keyLabel)

			if p11_module == nil || p11_module.Path == "" {
				return fmt.Errorf("PKCS#11 configuration not set")
			}

			// Initialize PKCS#11 token
			deviceID, err := s.InitPkcs11Token(p11_module)
			if err != nil {
				return fmt.Errorf("unable to initialize PKCS11 token: %v", err)
			}
			p11_module.DeviceID = deviceID

			// Set external reference
			if err := s.setAltExternalRef(keyLabel, key, p11_module); err != nil {
				return fmt.Errorf("unable to set external reference: %v", err)
			}

			// Check if an additional label for an alternative key is provided
			if len(altKeyLabel) > 0 {
				return fmt.Errorf("alt key label not allowed")
			}
		} else {
			ret := C.privateKey_loadAltKeyFromBuffer(key, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
			if ret != C.KRITIS3M_PKI_SUCCESS {
				return fmt.Errorf("PKI: failed to load alt private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
			}
		}
	} else {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	return nil
}

// initPkcs11Token initializes a PKCS#11 token
func (s *KRITIS3MPKI) InitPkcs11Token(p11_module *PKCS11Module) (int, error) {
	cModulePath := C.CString(p11_module.Path)
	defer C.free(unsafe.Pointer(cModulePath))

	var cPin *C.uint8_t
	if len(p11_module.Pin) > 0 {
		cPin = (*C.uint8_t)(unsafe.Pointer(&[]byte(p11_module.Pin)[0]))
	} else {
		cPin = nil
	}

	if p11_module.Slot <= 0 {
		// Slot is either a positive integer or -1 (default)
		p11_module.Slot = -1
	}

	deviceID := C.kritis3m_pki_init_entity_token(
		cModulePath,
		C.int(p11_module.Slot),
		cPin,
		C.size_t(len(p11_module.Pin)))

	if deviceID < C.KRITIS3M_PKI_SUCCESS {
		return 0, fmt.Errorf("failed to initialize entity token: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(C.int(deviceID))), deviceID)
	}

	return int(deviceID), nil
}

// SetExternalRef sets an external reference for PKCS#11 key
func (s *KRITIS3MPKI) setExternalRef(label string, key *C.PrivateKey, p11_module *PKCS11Module) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	ret := C.privateKey_setExternalRef(key, C.int(p11_module.DeviceID), cLabel)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to set external reference: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(ret)), ret)
	}
	return nil
}

func (s *KRITIS3MPKI) setAltExternalRef(label string, key *C.PrivateKey, p11_module *PKCS11Module) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	ret := C.privateKey_setAltExternalRef(key, C.int(p11_module.DeviceID), cLabel)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to set alt external reference: %s (%d)",
			C.GoString(C.kritis3m_pki_error_message(ret)), ret)
	}
	return nil
}

// GeneratePrivateKey generates a new private key
func (s *KRITIS3MPKI) GeneratePrivateKey(algorithm Algorithm) error {
	s.EntityKey = C.privateKey_new()
	cAlgorithm := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(cAlgorithm))
	s.Error.Code = int(C.privateKey_generateKey(s.EntityKey, cAlgorithm))
	if s.Error.Code != KRITIS3M_PKI_SUCCESS {
		return s.Error
	}
	return nil
}

// GeneratePrivateKeyAlt generates a new alternative private key
func (s *KRITIS3MPKI) GeneratePrivateKeyAlt(algorithm Algorithm) error {
	if s.EntityKey == nil {
		return fmt.Errorf("primary private key must be generated first")
	}
	cAlgorithm := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(cAlgorithm))
	s.Error.Code = int(C.privateKey_generateAltKey(s.EntityKey, cAlgorithm))
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
	if s.EntityKey != nil {
		C.privateKey_free(s.EntityKey)
	}
	if s.IssuerKey != nil {
		C.privateKey_free(s.IssuerKey)
	}
	if s.CSR != nil {
		C.signingRequest_free(s.CSR)
	}
	// Close PKCS#11 tokens
	C.kritis3m_pki_close_entity_token()
	C.kritis3m_pki_close_issuer_token()
}
