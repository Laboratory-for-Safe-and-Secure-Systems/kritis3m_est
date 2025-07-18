package realca

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/types"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
)

// BRSKIAdapter wraps a RealCA and implements the est.BRSKIRegistrar interface
type BRSKIAdapter struct {
	ca     *RealCA
	brski  *brski.ESTRegistrar
	logger common.Logger
}

// NewBRSKIAdapter creates a new BRSKI adapter that wraps the given RealCA
func NewBRSKIAdapter(ca *RealCA, config *types.RegistrarConfig) (*BRSKIAdapter, error) {
	// Get the domain CA certificate from the RealCA
	domainCA, err := ca.getDomainCACertificate()
	if err != nil {
		return nil, err
	}

	// Create the BRSKI registrar
	brskiRegistrar, err := brski.NewESTRegistrar(config, domainCA)
	if err != nil {
		return nil, err
	}

	return &BRSKIAdapter{
		ca:     ca,
		brski:  brskiRegistrar,
		logger: config.Logger,
	}, nil
}

// getDomainCACertificate extracts the domain CA certificate from the RealCA
func (ca *RealCA) getDomainCACertificate() (*x509.Certificate, error) {
	// For simplicity, we'll use the first certificate from the default backend
	if ca.defaultBackend != nil {
		if certs, exists := ca.backendCerts["default"]; exists && len(certs) > 0 {
			return certs[0], nil
		}
	}

	// Fallback to first available certificate
	for _, certs := range ca.backendCerts {
		if len(certs) > 0 {
			return certs[0], nil
		}
	}

	return nil, fmt.Errorf("no domain CA certificate available")
}

// Implement est.CA interface by delegating to the wrapped RealCA

func (a *BRSKIAdapter) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	return a.ca.CACerts(ctx, aps, r)
}

func (a *BRSKIAdapter) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return a.ca.CSRAttrs(ctx, aps, r)
}

func (a *BRSKIAdapter) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return a.ca.Enroll(ctx, csr, aps, r)
}

func (a *BRSKIAdapter) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return a.ca.Reenroll(ctx, cert, csr, aps, r)
}

func (a *BRSKIAdapter) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	return a.ca.ServerKeyGen(ctx, csr, aps, r)
}

// Implement est.BRSKIRegistrar interface by delegating to the BRSKI registrar

func (a *BRSKIAdapter) ProcessVoucherRequest(ctx context.Context, voucherRequestBytes []byte, aps string, r *http.Request) ([]byte, error) {
	return a.brski.ProcessVoucherRequest(ctx, voucherRequestBytes, aps, r)
}

func (a *BRSKIAdapter) ProcessVoucherStatus(ctx context.Context, serialNumber string, statusBytes []byte, aps string, r *http.Request) error {
	return a.brski.ProcessVoucherStatus(ctx, serialNumber, statusBytes, aps, r)
}

func (a *BRSKIAdapter) GetVoucher(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	return a.brski.GetVoucher(ctx, serialNumber, aps, r)
}

func (a *BRSKIAdapter) GetVoucherStatus(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	return a.brski.GetVoucherStatus(ctx, serialNumber, aps, r)
}

func (a *BRSKIAdapter) GetAuditLog(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	return a.brski.GetAuditLog(ctx, serialNumber, aps, r)
}

func (a *BRSKIAdapter) RevocationList(ctx context.Context, r *http.Request, aps string) ([]byte, error) {
	return a.ca.RevocationList(ctx, r, aps)
}
