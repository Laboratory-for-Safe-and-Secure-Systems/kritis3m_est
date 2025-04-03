package kritis3m_pki

/*
#cgo pkg-config: --static kritis3m_pki_client
#include "kritis3m_pki_client.h"
#include "kritis3m_pki_common.h"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// SigningRequestMetadata => x509.CertificateRequest
type SigningRequestMetadata struct {
	CSR *x509.CertificateRequest
}

func (s *SigningRequestMetadata) toC() *C.SigningRequestMetadata {
	var country, state, org, unit string

	if len(s.CSR.Subject.Country) > 0 {
		country = s.CSR.Subject.Country[0]
	} else {
		country = ""
	}

	if len(s.CSR.Subject.Province) > 0 {
		state = s.CSR.Subject.Province[0]
	} else {
		state = ""
	}

	if len(s.CSR.Subject.Organization) > 0 {
		org = s.CSR.Subject.Organization[0]
	} else {
		org = ""
	}

	if len(s.CSR.Subject.OrganizationalUnit) > 0 {
		unit = s.CSR.Subject.OrganizationalUnit[0]
	} else {
		unit = ""
	}

	// Convert URIs to strings
	var uriStrings []string
	for _, uri := range s.CSR.URIs {
		if uri != nil {
			uriStrings = append(uriStrings, uri.String())
		}
	}
	altNamesURI := strings.Join(uriStrings, ", ")

	// Convert IPAddresses to strings
	var ipStrings []string
	for _, ip := range s.CSR.IPAddresses {
		if ip != nil {
			ipStrings = append(ipStrings, ip.String())
		}
	}
	altNamesIP := strings.Join(ipStrings, ", ")

	return &C.SigningRequestMetadata{
		commonName:  C.CString(s.CSR.Subject.CommonName),
		country:     C.CString(country),
		state:       C.CString(state),
		org:         C.CString(org),
		unit:        C.CString(unit),
		altNamesDNS: C.CString(strings.Join(s.CSR.DNSNames, ", ")),
		altNamesURI: C.CString(altNamesURI),
		altNamesIP:  C.CString(altNamesIP),
	}
}

// CreateCSR creates a new Certificate Signing Request
func (s *KRITIS3MPKI) CreateCSR(metadata SigningRequestMetadata) error {
	s.CSR = C.signingRequest_new()

	ret := C.signingRequest_init(s.CSR, metadata.toC())
	if ret != C.KRITIS3M_PKI_SUCCESS {
		return fmt.Errorf("failed to initialize CSR: %s", C.GoString(C.kritis3m_pki_error_message(ret)))
	}
	return nil
}

// FinalizeCSR finalizes the CSR and returns it as a byte slice
func (s *KRITIS3MPKI) FinalizeCSR() (*x509.CertificateRequest, error) {
	var buffer [32 * 1024]byte
	var bufferSize C.size_t = C.size_t(len(buffer))
	s.Error.Code = int(C.signingRequest_finalize(s.CSR, s.EntityKey, (*C.uint8_t)(&buffer[0]), &bufferSize, false))
	if s.Error.Code != KRITIS3M_PKI_SUCCESS {
		return nil, s.Error
	}

	// Parse the buffer to a CSR PEM Block
	block, _ := pem.Decode(buffer[:bufferSize])
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %s", err)
	}
	return csr, nil
}
