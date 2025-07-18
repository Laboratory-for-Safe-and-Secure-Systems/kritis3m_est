package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// MockMASA represents a mock MASA server
type MockMASA struct {
	// MASA's private key and certificate
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate

	// Voucher database (in memory for simplicity)
	vouchers map[string]*Voucher

	// Audit log
	auditLog []*AuditLogEntry
}

// Voucher represents a BRSKI voucher
type Voucher struct {
	SerialNumber     string    `json:"serial-number"`
	CreatedOn        time.Time `json:"created-on"`
	ExpiresOn        time.Time `json:"expires-on"`
	Assertion        string    `json:"assertion"`
	PinnedDomainCert string    `json:"pinned-domain-cert"`
	Status           string    `json:"status"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	SerialNumber string    `json:"serial-number"`
	Timestamp    time.Time `json:"timestamp"`
	Action       string    `json:"action"`
	Details      string    `json:"details"`
}

// VoucherRequest represents a voucher request from a pledge
type VoucherRequest struct {
	SerialNumber string `json:"serial-number"`
	DomainCert   string `json:"domain-cert"`
	Nonce        string `json:"nonce"`
	Assertion    string `json:"assertion"`
}

// VoucherResponse represents a voucher response
type VoucherResponse struct {
	Voucher *Voucher `json:"voucher"`
}

func main() {
	// Generate MASA key pair and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create MASA certificate
	cert, err := createMASACertificate(privateKey)
	if err != nil {
		log.Fatalf("Failed to create MASA certificate: %v", err)
	}

	// Create mock MASA
	masa := &MockMASA{
		privateKey: privateKey,
		cert:       cert,
		vouchers:   make(map[string]*Voucher),
		auditLog:   make([]*AuditLogEntry, 0),
	}

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// BRSKI endpoints according to RFC 8995
	r.Route("/.well-known/brski", func(r chi.Router) {
		// /requestvoucher - MASA voucher request endpoint
		r.Post("/requestvoucher", masa.handleRequestVoucher)

		// /requestauditlog - MASA audit log endpoint
		r.Get("/requestauditlog", masa.handleRequestAuditLog)
	})

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("MASA server is running"))
	})

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  privateKey,
			},
		},
	}

	// Create server
	server := &http.Server{
		Addr:      ":8444", // MASA runs on different port
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	log.Printf("Mock MASA server starting on :8444")
	log.Printf("MASA certificate subject: %s", cert.Subject)
	log.Printf("MASA certificate issuer: %s", cert.Issuer)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start MASA server: %v", err)
	}
}

// createMASACertificate creates a self-signed certificate for the MASA
func createMASACertificate(privateKey *rsa.PrivateKey) (*x509.Certificate, error) {
	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Mock MASA Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"123 MASA Street"},
			PostalCode:    []string{"94105"},
			CommonName:    "masa.example.com",
		},
		Issuer: pkix.Name{
			Organization:  []string{"Mock MASA Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"123 MASA Street"},
			PostalCode:    []string{"94105"},
			CommonName:    "masa.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"masa.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// handleRequestVoucher handles voucher requests from pledges
func (m *MockMASA) handleRequestVoucher(w http.ResponseWriter, r *http.Request) {
	// Parse voucher request
	var voucherReq VoucherRequest
	if err := json.NewDecoder(r.Body).Decode(&voucherReq); err != nil {
		http.Error(w, "Invalid voucher request", http.StatusBadRequest)
		return
	}

	log.Printf("Received voucher request for serial number: %s", voucherReq.SerialNumber)

	// Create voucher
	voucher := &Voucher{
		SerialNumber:     voucherReq.SerialNumber,
		CreatedOn:        time.Now(),
		ExpiresOn:        time.Now().AddDate(0, 0, 1), // Valid for 1 day
		Assertion:        "verified",                  // Mock assertion
		PinnedDomainCert: voucherReq.DomainCert,
		Status:           "valid",
	}

	// Store voucher
	m.vouchers[voucherReq.SerialNumber] = voucher

	// Add audit log entry
	auditEntry := &AuditLogEntry{
		SerialNumber: voucherReq.SerialNumber,
		Timestamp:    time.Now(),
		Action:       "voucher_requested",
		Details:      "Voucher requested by pledge",
	}
	m.auditLog = append(m.auditLog, auditEntry)

	// Create response
	response := VoucherResponse{
		Voucher: voucher,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	log.Printf("Issued voucher for serial number: %s", voucherReq.SerialNumber)
}

// handleRequestAuditLog handles audit log requests
func (m *MockMASA) handleRequestAuditLog(w http.ResponseWriter, r *http.Request) {
	serialNumber := r.URL.Query().Get("serial-number")
	if serialNumber == "" {
		http.Error(w, "Missing serial-number parameter", http.StatusBadRequest)
		return
	}

	log.Printf("Audit log request for serial number: %s", serialNumber)

	// Filter audit log entries for the requested serial number
	var entries []*AuditLogEntry
	for _, entry := range m.auditLog {
		if entry.SerialNumber == serialNumber {
			entries = append(entries, entry)
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(entries)

	log.Printf("Returned %d audit log entries for serial number: %s", len(entries), serialNumber)
}
