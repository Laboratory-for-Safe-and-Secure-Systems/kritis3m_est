package realca

/*
#cgo CFLAGS: -I../../include/kritis3m_pki -I../../include/liboqs -I../../include/oqs -I../../include
#cgo LDFLAGS: -L../../lib -lkritis3m_pki
#include "common.h"
*/
import "C"
import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ayham/est"
	"github.com/ayham/est/internal/tpm"
	"github.com/globalsign/pemfile"
	"go.mozilla.org/pkcs7"
)

// Global variables.
var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// Global constants.
const (
	alphanumerics              = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bitSizeHeader              = "Bit-Size"
	csrAttrsAPS                = "csrattrs"
	defaultCertificateDuration = time.Hour * 24 * 90
	serverKeyGenPassword       = "pseudohistorical"
	rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS           = "triggererrors"
)

const (
	pkcs8PrivateKeyPEMType = "PRIVATE KEY"
	pkcs1PrivateKeyPEMType = "RSA PRIVATE KEY"
	ecPrivateKeyPEMType    = "EC PRIVATE KEY"
	pkixPublicKeyPEMType   = "PUBLIC KEY"
	pkcs1PublicKeyPEMType  = "RSA PUBLIC KEY"
)

// RealCA is a simple CA implementation that uses a single key pair and
// certificate to sign requests.
// It uses Root 1 Intermediate 2 Entity hierarchy.
type RealCA struct {
	certs []*x509.Certificate
	key   interface{}
	pqKey interface{}
}

// New creates a new mock certificate authority. If more than one CA certificate
// is provided, they should be in order with the issuing (intermediate) CA
// certificate first, and the root CA certificate last. The private key should
// be associated with the public key in the first, issuing CA certificate.
func New(cacerts []*x509.Certificate, key interface{}) (*RealCA, error) {
	if len(cacerts) < 1 {
		return nil, errors.New("no CA certificates provided")
	} else if key == nil {
		return nil, errors.New("no private key provided")
	}

	for i := range cacerts {
		if !cacerts[i].IsCA {
			return nil, fmt.Errorf("certificate at index %d is not a CA certificate", i)
		}
	}

	return &RealCA{
		certs: cacerts,
		key:   key,
	}, nil
}

// Load CA certificates and key from PEM files.
func (ca *RealCA) Load(certFile, keyFile string) (*RealCA, error) {
	blocks, err := pemfile.ReadBlocks(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	var certs []*x509.Certificate
	var key interface{}

	for _, block := range blocks {
		if err := pemfile.IsType(block, "CERTIFICATE"); err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)

	}

	// Read private key
	blocks, err = pemfile.ReadBlocks(keyFile)
	for _, block := range blocks {
		err = pemfile.IsType(block, pkcs8PrivateKeyPEMType, pkcs1PrivateKeyPEMType, ecPrivateKeyPEMType)
		if err != nil {
			return nil, err
		}

		switch block.Type {
		case pkcs8PrivateKeyPEMType:
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

		case pkcs1PrivateKeyPEMType:
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)

		case ecPrivateKeyPEMType:
			key, err = x509.ParseECPrivateKey(block.Bytes)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	log.Printf("Loaded CA certificates and key from %s and %s", certFile, keyFile)

	return New(certs, key)
}

// CACerts returns the CA certificates, unless the additional path segment is
// "triggererrors", in which case an error is returned for testing purposes.
func (ca *RealCA) CACerts(
	ctx context.Context,
	aps string,
	r *http.Request,
) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	return ca.certs, nil
}

// CSRAttrs returns an empty sequence of CSR attributes, unless the additional
// path segment is:
//   - "csrattrs", in which case it returns the same example sequence described
//     in RFC7030 4.5.2; or
//   - "triggererrors", in which case an error is returned for testing purposes.
func (ca *RealCA) CSRAttrs(
	ctx context.Context,
	aps string,
	r *http.Request,
) (attrs est.CSRAttrs, err error) {
	switch aps {
	case csrAttrsAPS:
		attrs = est.CSRAttrs{
			OIDs: []asn1.ObjectIdentifier{
				{1, 2, 840, 113549, 1, 9, 7},
				{1, 2, 840, 10045, 4, 3, 3},
			},
			Attributes: []est.Attribute{
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 6, 1, 1, 1, 1, 22}},
				},
				{
					Type:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
					Values: est.AttributeValueSET{asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
				},
			},
		}

	case triggerErrorsAPS:
		err = errors.New("triggered error")
	}

	return attrs, err
}

// Enroll issues a new certificate with:
//   - a 90 day duration from the current time
//   - a randomly generated 128-bit serial number
//   - a subject and subject alternative name copied from the provided CSR
//   - a default set of key usages and extended key usages
//   - a basic constraints extension with cA flag set to FALSE
//
// unless the additional path segment is "triggererrors", in which case the
// following errors will be returned for testing purposes, depending on the
// common name in the CSR:
//
//   - "Trigger Error Forbidden", HTTP status 403
//   - "Trigger Error Deferred", HTTP status 202 with retry of 600 seconds
//   - "Trigger Error Unknown", untyped error expected to be interpreted as
//     an internal server error.
func (ca *RealCA) Enroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	// Generate certificate template, copying the raw subject and raw
	// SubjectAltName extension from the CSR.
	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))

	if err != nil {
		return nil, fmt.Errorf("failed to make serial number: %w", err)
	}

	ski, err := makePublicKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make public key identifier: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCertificateDuration)
	if latest := ca.certs[0].NotAfter.Sub(notAfter); latest < 0 {
		// Don't issue any certificates which expire after the CA certificate.
		notAfter = ca.certs[0].NotAfter
	}

	var tmpl = &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             now,
		NotAfter:              notAfter,
		RawSubject:            csr.RawSubject,
		SubjectKeyId:          ski,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	// Create and return certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.certs[0], csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Reenroll implements est.CA but simply passes the request through to Enroll.
func (ca *RealCA) Reenroll(
	ctx context.Context,
	cert *x509.Certificate,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, error) {
	return ca.Enroll(ctx, csr, aps, r)
}

// ServerKeyGen creates a new RSA private key and then calls Enroll. It returns
// the key in PKCS8 DER-encoding, unless the additional path segment is set to
// "pkcs7", in which case it is returned wrapped in a CMS SignedData structure
// signed by the CA certificate(s), itself wrapped in a CMS EnvelopedData
// encrypted with the pre-shared key "pseudohistorical". A "Bit-Size" HTTP
// header may be passed with the values 2048, 3072 or 4096.
func (ca *RealCA) ServerKeyGen(
	ctx context.Context,
	csr *x509.CertificateRequest,
	aps string,
	r *http.Request,
) (*x509.Certificate, []byte, error) {
	bitsize := 2048
	if r != nil && r.Header != nil {
		if v := r.Header.Get(bitSizeHeader); v != "" {
			var err error
			bitsize, err = strconv.Atoi(v)
			if err != nil || (bitsize != 2048 && bitsize != 3072 && bitsize != 4096) {
				return nil, nil, caError{
					status: http.StatusBadRequest,
					desc:   "invalid bit size value",
				}
			}
		}
	}

	// Generate new key.
	key, err := rsa.GenerateKey(rand.Reader, bitsize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Copy raw subject and raw SubjectAltName extension from client CSR into
	// a new CSR signed by the new private key.
	tmpl := &x509.CertificateRequest{
		RawSubject: csr.RawSubject,
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	newCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	// Enroll for certificate using the new CSR signed with the new key.
	cert, err := ca.Enroll(ctx, newCSR, aps, r)
	if err != nil {
		return nil, nil, err
	}

	// Marshal generated private key.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Based on value of additional path segment, return private key either
	// as a DER-encoded PKCS8 PrivateKeyInfo structure, or as that structure
	// wrapped in a CMS SignedData inside a CMS EnvelopedData structure.
	var retDER []byte

	switch aps {
	case "pkcs7":
		// Create the CMS SignedData structure.
		signedData, err := pkcs7.NewSignedData(keyDER)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CMS SignedData: %w", err)
		}

		for i, cert := range ca.certs {
			if i == 0 {
				err := signedData.AddSigner(cert, ca.key, pkcs7.SignerInfoConfig{})
				if err != nil {
					return nil, nil, fmt.Errorf("failed to add signed to CMS SignedData: %w", err)
				}
			} else {
				signedData.AddCertificate(cert)
			}
		}

		sdBytes, err := signedData.Finish()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to finish CMS SignedData: %w", err)
		}

		// Encrypt the CMS SignedData in a CMS EnvelopedData structure.
		retDER, err = pkcs7.EncryptUsingPSK(sdBytes, []byte(serverKeyGenPassword))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CMS EnvelopedData: %w", err)
		}

	default:
		retDER = keyDER
	}

	return cert, retDER, nil
}

// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
// protocol. An EK certificate chain with a length of at least one must be
// provided, along with the EK and AK public areas. The return values are an
// encrypted credential, a wrapped encryption key, and the certificate itself
// encrypted with the encrypted credential in AES 128 Galois Counter Mode
// inside a CMS EnvelopedData structure.
func (ca *RealCA) TPMEnroll(
	ctx context.Context,
	csr *x509.CertificateRequest,
	ekcerts []*x509.Certificate,
	ekPub, akPub []byte,
	aps string,
	r *http.Request,
) ([]byte, []byte, []byte, error) {
	cert, err := ca.Enroll(ctx, csr, aps, r)
	if err != nil {
		return nil, nil, nil, err
	}

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate AES key random bytes: %w", err)
	}

	blob, secret, err := tpm.MakeCredential(key, ekPub, akPub)
	if err != nil {
		return nil, nil, nil, err
	}

	cred, err := pkcs7.EncryptUsingPSK(cert.Raw, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CMS EnvelopedData: %w", err)
	}

	return blob, secret, cred, err
}

// makePublicKeyIdentifier builds a public key identifier in accordance with the
// first method described in RFC5280 section 4.2.1.2.
func makePublicKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}

// makeRandomIdentifier makes a random alphanumeric identifier of length n.
func makeRandomIdentifier(n int) (string, error) {
	var id = make([]byte, n)

	for i := range id {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumerics))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}

		id[i] = alphanumerics[idx.Int64()]
	}

	return string(id), nil
}
