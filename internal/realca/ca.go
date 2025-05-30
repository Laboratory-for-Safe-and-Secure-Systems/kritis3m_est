package realca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/db"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/kritis3m_pki"
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
	defaultCertificateDuration = 4 // in days
	serverKeyGenPassword       = "pseudohistorical"
	rootCertificateDuration    = time.Hour * 24
	triggerErrorsAPS           = "triggererrors"
)

// PKIBackendConfig represents the configuration for a PKI backend
type PKIBackendConfig struct {
	APS          string                     `json:"aps"`
	Module       *kritis3m_pki.PKCS11Module `json:"pkcs11_module,omitempty"`
	Certificates string                     `json:"certificates"`
	PrivateKey   string                     `json:"private_key"`
}

// RealCA is a simple CA implementation that uses a single key pair and
// certificate to sign requests.
// It uses Root 1 Intermediate 2 Entity hierarchy.
type RealCA struct {
	backends       map[string]*kritis3m_pki.KRITIS3MPKI
	defaultBackend *kritis3m_pki.KRITIS3MPKI
	database       *db.DB
	logger         est.Logger
	validity       int
	backendCerts   map[string][]*x509.Certificate
	backendKeys    map[string]any
}

// New creates a new mock certificate authority. If more than one CA certificate
// is provided, they should be in order with the issuing (intermediate) CA
// certificate first, and the root CA certificate last. The private key should
// be associated with the public key in the first, issuing CA certificate.
func New(backends []PKIBackendConfig, defaultBackend *PKIBackendConfig, logger est.Logger, validity int) (*RealCA, error) {
	if len(backends) == 0 && defaultBackend == nil {
		return nil, errors.New("no CA backends provided")
	}

	ca := &RealCA{
		backends:     make(map[string]*kritis3m_pki.KRITIS3MPKI),
		backendCerts: make(map[string][]*x509.Certificate),
		backendKeys:  make(map[string]any),
		logger:       logger,
		validity:     validity,
	}

	// Initialize default backend if provided
	if defaultBackend != nil {
		defaultPKI, certs, key, err := initializeBackend(defaultBackend)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize default backend: %w", err)
		}
		ca.defaultBackend = defaultPKI
		ca.backendCerts["default"] = certs
		ca.backendKeys["default"] = key
	}

	// Initialize APS-specific backends
	for _, backend := range backends {
		if backend.APS == "" {
			return nil, errors.New("backend APS cannot be empty")
		}

		pki, certs, key, err := initializeBackend(&backend)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize backend for APS %s: %w", backend.APS, err)
		}
		ca.backends[backend.APS] = pki
		ca.backendCerts[backend.APS] = certs
		ca.backendKeys[backend.APS] = key
	}

	database, err := db.NewDB("sqlite", "test.db", logger)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sqlite database: %w", err)
	}
	logger.Infof("Successfully connected to SQLite!")
	ca.database = database

	return ca, nil
}

func initializeBackend(backend *PKIBackendConfig) (*kritis3m_pki.KRITIS3MPKI, []*x509.Certificate, interface{}, error) {
	if backend.Certificates == "" {
		return nil, nil, nil, errors.New("no certificates provided")
	}

	certData, err := os.ReadFile(backend.Certificates)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse certificates
	certs, err := parseCertificates(certData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse certificates: %w", err)
	}

	pkcs11Config := kritis3m_pki.PKCS11Config{
		EntityModule: nil,
		IssuerModule: &kritis3m_pki.PKCS11Module{
			Path: backend.Module.Path,
			Pin:  backend.Module.Pin,
			Slot: backend.Module.Slot,
		},
	}

	kritis3m_pki.Kritis3mPKI.LoadPKCS11Config(pkcs11Config)

	keyData, key, err := kritis3m_pki.Kritis3mPKI.LoadPrivateKey(backend.PrivateKey, kritis3m_pki.Kritis3mPKI.PKCS11.IssuerModule)
	if err == nil {
		kritis3m_pki.Kritis3mPKI.IssuerKey = key
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	err = kritis3m_pki.Kritis3mPKI.LoadIssuerCert(certData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load issuer cert: %w", err)
	}

	return kritis3m_pki.Kritis3mPKI, certs, keyData, nil
}

// getBackend returns the appropriate PKI backend for the given APS
func (ca *RealCA) getBackend(aps string) (*kritis3m_pki.KRITIS3MPKI, []*x509.Certificate, interface{}) {
	if backend, exists := ca.backends[aps]; exists {
		return backend, ca.backendCerts[aps], ca.backendKeys[aps]
	}
	return ca.defaultBackend, ca.backendCerts["default"], ca.backendKeys["default"]
}

// CACerts returns the CA certificates for the specified APS
func (ca *RealCA) CACerts(
	ctx context.Context,
	aps string,
	r *http.Request,
) ([]*x509.Certificate, error) {
	if aps == triggerErrorsAPS {
		return nil, errors.New("triggered error")
	}

	// save the request to the database
	err := ca.database.SaveHTTPRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to save request: %w", err)
	}

	_, certs, _ := ca.getBackend(aps)
	return certs, nil
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

	// Get the appropriate PKI backend for this APS
	backend, certs, _ := ca.getBackend(aps)
	if backend == nil {
		return nil, fmt.Errorf("no PKI backend available for APS: %s", aps)
	}

	// Create certificate using the selected PKI backend
	err := backend.CreateCertificate(csr.Raw, ca.validity, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Finalize the certificate
	pemCertData, err := backend.FinalizeCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize certificate: %w", err)
	}

	// Decode PEM to get DER
	block, _ := pem.Decode(pemCertData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate")
	}

	derCertData := block.Bytes

	// Parse the certificate
	cert, err := x509.ParseCertificate(derCertData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// verify the certificate
	if (cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm) && (certs[0].PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm) {
		err = cert.CheckSignatureFrom(certs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate: %w", err)
		}
	}

	// Use the hex serial for database operations
	hexSerialString := strings.ToUpper(cert.SerialNumber.Text(16))
	ca.logger.Debugf("Serial number: %s", hexSerialString)
	subjectFromDB, found := ca.database.GetSubject(cert.Subject.CommonName)
	ca.logger.Debugf("Subject from DB: %v", subjectFromDB.CommonName)

	if found {
		err = ca.database.UpdateSubject(cert.Subject.CommonName, map[string]interface{}{
			"reenrolled":     true,
			"reenrolled_at":  time.Now(),
			"reenroll_count": subjectFromDB.ReenrollCount + 1,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to update certificate: %w", err)
		}

		err = ca.database.SaveCertificateFromSubject(cert.Subject.CommonName, *cert)
		if err != nil {
			return nil, fmt.Errorf("failed to save certificate: %w", err)
		}

		ca.logger.Infof("Certificate reenrolled for %s with serial number %s", cert.Subject.CommonName, hexSerialString)

		ca.database.DisablePreviousCerts(cert.Subject.CommonName, hexSerialString)

		ca.logger.Debugf("Revoking previous certificates for %s", cert.Subject.CommonName)
	} else {
		err = ca.database.SaveCertificateFromSubject(cert.Subject.CommonName, *cert)
		if err != nil {
			return nil, fmt.Errorf("failed to save certificate: %w", err)
		}
	}

	// save the request to the database
	err = ca.database.SaveHTTPRequest(r)
	if err != nil {
		return nil, fmt.Errorf("failed to save request: %w", err)
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

// parseCertificates parses a PEM-encoded certificate chain
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected CERTIFICATE, got %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
		data = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}
	return certs, nil
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
		// Get the appropriate backend for this APS
		_, backendCerts, backendKeys := ca.getBackend(aps)

		// Create the CMS SignedData structure.
		signedData, err := pkcs7.NewSignedData(keyDER)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create CMS SignedData: %w", err)
		}

		// Type assert the backend keys to the correct type
		keys, ok := backendKeys.([]crypto.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("invalid backend keys type")
		}

		// Add the first certificate as a signer and the rest as certificates
		if len(backendCerts) > 0 && len(keys) > 0 {
			err := signedData.AddSigner(backendCerts[0], keys[0], pkcs7.SignerInfoConfig{})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to add signer to CMS SignedData: %w", err)
			}
			for _, cert := range backendCerts[1:] {
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

func (ca *RealCA) RevocationList(ctx context.Context, r *http.Request, aps string) ([]byte, error) {
	revokedCerts, found := ca.database.GetRevocations()
	if !found {
		return nil, fmt.Errorf("failed to get revoked certificates")
	}
	if len(revokedCerts) == 0 {
		return nil, nil
	}

	revokedCertificates := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, cert := range revokedCerts {
		serialNumber, err := new(big.Int).SetString(cert.SerialNumber, 16)
		if !err {
			return nil, fmt.Errorf("failed to parse serial number")
		}
		revokedCertificates[i] = pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: cert.RevokedAt,
		}
	}

	// Create a new RevocationList
	revocationList := &x509.RevocationList{
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Hour * 24),
	}

	// Get the appropriate backend for this APS
	_, _, backendKeys := ca.getBackend(aps)

	// PEM to DER
	block, _ := pem.Decode(backendKeys.([]byte))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	// Load Key from PEM -> ca.backendKeys[aps].(*ecdsa.PrivateKey)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Compare the public key in the certificate with the public key in the private key
	if !bytes.Equal(ca.backendCerts[aps][0].PublicKey.(*ecdsa.PublicKey).X.Bytes(), key.(*ecdsa.PrivateKey).PublicKey.X.Bytes()) {
		return nil, fmt.Errorf("public key in the certificate does not match the public key in the private key")
	}

	list, err := x509.CreateRevocationList(rand.Reader, revocationList, ca.backendCerts[aps][0], key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation list: %w", err)
	}

	// Save the request to the database
	if err := ca.database.SaveHTTPRequest(r); err != nil {
		ca.logger.Errorf("Failed to save HTTP request: %v", err)
	}

	return list, nil
}
