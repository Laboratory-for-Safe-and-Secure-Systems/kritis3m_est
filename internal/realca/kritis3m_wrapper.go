package realca

/*
#cgo pkg-config: --static kritis3m_pki_server
#include "kritis3m_pki_server.h"
#include "kritis3m_pki_common.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/pem"
	"fmt"
	"unsafe"
)

// KRITIS3MPKI represents the PKI configuration and operations
type KRITIS3MPKI struct {
	OutputCert *C.OutputCert
	IssuerCert *C.IssuerCert
	PrivateKey *C.PrivateKey
	// CSR        *C.SigningRequest
}

// NewKRITIS3MPKI creates a new KRITIS3MPKI instance
func NewKRITIS3MPKI() *KRITIS3MPKI {
	return &KRITIS3MPKI{}
}

// LoadPrivateKey loads a private key from a PEM-encoded buffer
func (s *KRITIS3MPKI) LoadPrivateKey(keyData []byte) error {
	s.PrivateKey = C.privateKey_new()
	ret := C.privateKey_loadKeyFromBuffer(s.PrivateKey, (*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to load private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
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
func (s *KRITIS3MPKI) GeneratePrivateKey(algorithm string) error {
	s.PrivateKey = C.privateKey_new()
	cAlgorithm := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlgorithm))
	ret := C.privateKey_generateKey(s.PrivateKey, cAlgorithm)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to generate private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

// GeneratePrivateKeyAlt generates a new alternative private key
func (s *KRITIS3MPKI) GeneratePrivateKeyAlt(algorithm string) error {
	if s.PrivateKey == nil {
		return fmt.Errorf("primary private key must be generated first")
	}
	cAlgorithm := C.CString(algorithm)
	defer C.free(unsafe.Pointer(cAlgorithm))
	ret := C.privateKey_generateAltKey(s.PrivateKey, cAlgorithm)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to generate alternative private key: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

// LoadIssuerCert loads an issuer certificate from a PEM-encoded buffer
func (s *KRITIS3MPKI) LoadIssuerCert(certData []byte) error {
	s.IssuerCert = C.issuerCert_new()

	ret := C.issuerCert_initFromBuffer(s.IssuerCert, (*C.uint8_t)(&certData[0]), C.size_t(len(certData)), (*C.PrivateKey)(s.PrivateKey))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to load issuer certificate: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

// // CreateCSR creates a new Certificate Signing Request
// func (s *ASLPKI) CreateCSR(cn, o, ou, altName string) error {
// 	s.CSR = C.signingRequest_new()
// 	metadata := C.SigningRequestMetadata{
// 		CN:      C.CString(cn),
// 		O:       C.CString(o),
// 		OU:      C.CString(ou),
// 		altName: C.CString(altName),
// 	}
// 	defer func() {
// 		C.free(unsafe.Pointer(metadata.CN))
// 		C.free(unsafe.Pointer(metadata.O))
// 		C.free(unsafe.Pointer(metadata.OU))
// 		C.free(unsafe.Pointer(metadata.altName))
// 	}()

// 	ret := C.signingRequest_init(s.CSR, &metadata)
// 	if ret != C.KRITIS3M_PKI_SUCCESS {
// 		return fmt.Errorf("failed to initialize CSR: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
// 	}
// 	return nil
// }

// // FinalizeCSR finalizes the CSR and returns it as a byte slice
// func (s *ASLPKI) FinalizeCSR() ([]byte, error) {
// 	var buffer [32 * 1024]byte
// 	var bufferSize C.size_t = C.size_t(len(buffer))
// 	ret := C.signingRequest_finalize(s.CSR, s.PrivateKey, (*C.uint8_t)(&buffer[0]), &bufferSize)
// 	if ret != C.KRITIS3M_PKI_SUCCESS {
// 		return nil, fmt.Errorf("failed to finalize CSR: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
// 	}
// 	return buffer[:bufferSize], nil
// }

// CreateCertificate creates a new certificate from a CSR
func (s *KRITIS3MPKI) CreateCertificate(csrData []byte, validity int, isCA bool) error {

	// Convert DER to PEM
	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrData,
	})

	if pemCSR == nil {
		return fmt.Errorf("failed to encode CSR to PEM")
	}

	fmt.Println("PEM CSR: ", string(pemCSR))

	s.OutputCert = C.outputCert_new()
	ret := C.outputCert_initFromCsr(s.OutputCert, (*C.uint8_t)(unsafe.Pointer(&pemCSR[0])), C.size_t(len(pemCSR)))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI Create Certificate failed: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}

	ret = C.outputCert_setIssuerData(s.OutputCert, s.IssuerCert, s.PrivateKey)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to set issuer data: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}

	C.outputCert_setValidity(s.OutputCert, C.int(validity))

	if isCA {
		ret = C.outputCert_configureAsCA(s.OutputCert)
	} else {
		ret = C.outputCert_configureAsEntity(s.OutputCert)
	}
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to configure cert: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}

	return nil
}

// FinalizeCertificate finalizes the certificate and returns it as a byte slice
func (s *KRITIS3MPKI) FinalizeCertificate() ([]byte, error) {
	var buffer [32 * 1024]byte
	var bufferSize C.size_t = C.size_t(len(buffer))
	ret := C.outputCert_finalize(s.OutputCert, s.PrivateKey, (*C.uint8_t)(&buffer[0]), &bufferSize)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return nil, fmt.Errorf("failed to finalize certificate: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return buffer[:bufferSize], nil
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
	// if s.CSR != nil {
	// 	C.signingRequest_free(s.CSR)
	// }
}
