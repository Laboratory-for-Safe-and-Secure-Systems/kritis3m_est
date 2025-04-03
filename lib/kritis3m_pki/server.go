package kritis3m_pki

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

// LoadIssuerCert loads an issuer certificate from a PEM-encoded buffer
func (s *KRITIS3MPKI) LoadIssuerCert(certData []byte) error {
	s.IssuerCert = C.inputCert_new()

	ret := C.inputCert_initFromBuffer(s.IssuerCert, (*C.uint8_t)(&certData[0]), C.size_t(len(certData)), (*C.PrivateKey)(s.IssuerKey))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI: failed to load issuer certificate: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

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

	s.OutputCert = C.outputCert_new()
	ret := C.outputCert_initFromCsr(s.OutputCert, (*C.uint8_t)(unsafe.Pointer(&pemCSR[0])), C.size_t(len(pemCSR)))
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("PKI Create Certificate failed: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}

	ret = C.outputCert_setIssuerData(s.OutputCert, s.IssuerCert, s.IssuerKey)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to set issuer data: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}

	C.outputCert_setValidity(s.OutputCert, C.int(validity))

	if isCA {
		ret = C.outputCert_configureAsCA(s.OutputCert)
	} else {
		ret = C.outputCert_configureAsMachineEntity(s.OutputCert)
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
	ret := C.outputCert_finalize(s.OutputCert, s.IssuerKey, (*C.uint8_t)(&buffer[0]), &bufferSize)
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return nil, fmt.Errorf("failed to finalize certificate: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return buffer[:bufferSize], nil
}
