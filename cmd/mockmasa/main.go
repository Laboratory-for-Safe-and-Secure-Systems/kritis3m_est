package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
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
	// Create MASA certificate
	cert, privateKey, err := createMASACertificate()
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

	// Create TLS configuration for MASA
	// For testing purposes, we'll accept any client certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
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
func createMASACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load MASA Cert from file
	certData, err := os.ReadFile("./certs/vendor.crt")
	if err != nil {
		return nil, nil, err
	}

	// Decode certificate
	certDER, rest := pem.Decode(certData)
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("unexpected data after certificate")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load private key from file
	privateKeyBytes, err := os.ReadFile("./certs/vendor.key")
	if err != nil {
		return nil, nil, err
	}

	// Decode private key
	privateKeyDER, rest := pem.Decode(privateKeyBytes)
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("unexpected data after private key")
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey.(*rsa.PrivateKey), nil
}

// handleRequestVoucher handles voucher requests from pledges
func (m *MockMASA) handleRequestVoucher(w http.ResponseWriter, r *http.Request) {
	// Check content type - accept both application/json and application/jose+json
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" && contentType != "application/jose+json" {
		http.Error(w, "Invalid content type, expected application/json or application/jose+json", http.StatusBadRequest)
		return
	}

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

	// Send response - use the same content type as the request
	responseContentType := "application/json"
	if contentType == "application/jose+json" {
		responseContentType = "application/jose+json"
	}
	w.Header().Set("Content-Type", responseContentType)
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
