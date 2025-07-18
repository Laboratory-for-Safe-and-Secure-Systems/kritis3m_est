package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	// Import the internal EST client library
	"bytes"
	"io"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/voucher"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
)

// MockPledge represents a mock BRSKI pledge
type MockPledge struct {
	// Pledge's private key and certificate
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate

	// Serial number for this pledge
	serialNumber string

	// BRSKI state
	brskiState *BRSKIState

	// EST client for enrollment (connects to local registrar)
	estClient *est.Client

	// Logger
	logger common.Logger
}

// BRSKIState represents the BRSKI enrollment state
type BRSKIState struct {
	Status          string            `json:"status"`
	VoucherReceived bool              `json:"voucher_received"`
	Enrolled        bool              `json:"enrolled"`
	EnrollmentCert  *x509.Certificate `json:"-"`
	EnrollmentKey   *rsa.PrivateKey   `json:"-"`
	LastActivity    time.Time         `json:"last_activity"`
}

// Note: Using internal library types for VoucherRequest, Voucher, etc.
// from github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/voucher

// mockLogger implements the common.Logger interface for the mock pledge
type mockLogger struct{}

func (l *mockLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func (l *mockLogger) Errorw(msg string, keysAndValues ...interface{}) {
	log.Printf("[ERROR] %s", msg)
}

func (l *mockLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *mockLogger) Infow(msg string, keysAndValues ...interface{}) {
	log.Printf("[INFO] %s", msg)
}

func (l *mockLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

func (l *mockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	log.Printf("[DEBUG] %s", msg)
}

func (l *mockLogger) With(keysAndValues ...interface{}) common.Logger {
	return l
}

func (l *mockLogger) Info() common.LogEvent {
	return &mockLogEvent{}
}

func (l *mockLogger) Fatal() common.LogEvent {
	return &mockLogEvent{}
}

type mockLogEvent struct{}

func (e *mockLogEvent) Msg(msg string)                          {}
func (e *mockLogEvent) Msgf(format string, args ...interface{}) {}
func (e *mockLogEvent) Err(err error) common.LogEvent           { return e }
func (e *mockLogEvent) Str(key, val string) common.LogEvent     { return e }
func (e *mockLogEvent) Int(key string, val int) common.LogEvent { return e }

func main() {
	// Create pledge certificate
	cert, privateKey, err := createPledgeCertificate()
	if err != nil {
		log.Fatalf("Failed to create pledge certificate: %v", err)
	}

	// Generate unique serial number
	serialNumber := fmt.Sprintf("PLEDGE-%d", time.Now().Unix())

	// Create logger
	logger := &mockLogger{}

	// Create EST client that connects to the local registrar (not MASA)
	// The pledge is air-gapped and can only reach the local registrar
	estClient := &est.Client{
		Host:               "localhost:8443", // Local registrar EST server
		CertificatePath:    "./certs/pledge1.crt",
		PrivateKeyPath:     "./certs/pledge1.key",
		InsecureSkipVerify: true, // For testing only
	}

	// Create mock pledge
	pledge := &MockPledge{
		privateKey:   privateKey,
		cert:         cert,
		serialNumber: serialNumber,
		estClient:    estClient,
		logger:       logger,
		brskiState: &BRSKIState{
			Status:          "initialized",
			VoucherReceived: false,
			Enrolled:        false,
			LastActivity:    time.Now(),
		},
	}

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Pledge endpoints
	r.Get("/status", pledge.handleStatus)
	r.Post("/enroll", pledge.handleEnroll)
	r.Post("/request-voucher", pledge.handleRequestVoucher)

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Mock pledge is running"))
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
		Addr:      ":8445", // Pledge runs on different port
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	log.Printf("Mock pledge starting on :8445")
	log.Printf("Pledge serial number: %s", serialNumber)
	log.Printf("Pledge certificate subject: %s", cert.Subject)
	log.Printf("Pledge is air-gapped and will only communicate with local registrar at localhost:8443")

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start pledge server: %v", err)
	}
}

// createPledgeCertificate creates a self-signed certificate for the pledge
func createPledgeCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load certificate from file
	bytePem, err := os.ReadFile("./certs/pledge1.crt")
	if err != nil {
		return nil, nil, err
	}

	// Decode certificate
	certDER, _ := pem.Decode(bytePem)

	// Check if certificate is valid
	if certDER.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("certificate is not a valid PEM certificate")
	}

	// Load private key from file
	privateKeyBytes, err := os.ReadFile("./certs/pledge1.key")
	if err != nil {
		return nil, nil, err
	}

	// Decode private key PEM
	privateKeyDER, _ := pem.Decode(privateKeyBytes)
	if privateKeyDER == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey.(*rsa.PrivateKey), nil
}

// handleStatus returns the current BRSKI status
func (p *MockPledge) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(p.brskiState)
}

// handleRequestVoucher initiates BRSKI voucher request
func (p *MockPledge) handleRequestVoucher(w http.ResponseWriter, r *http.Request) {
	p.logger.Infof("Starting BRSKI voucher request for pledge %s", p.serialNumber)

	// Step 1: Get domain certificate from local registrar using the EST client
	// The pledge is air-gapped and can only reach the local registrar
	domainCerts, err := p.getDomainCertificate()
	if err != nil {
		p.logger.Errorf("Failed to get domain certificate from local registrar: %v", err)
		http.Error(w, "Failed to get domain certificate from local registrar", http.StatusInternalServerError)
		return
	}

	// Step 2: Request voucher from local registrar (not MASA directly)
	// The registrar will proxy the request to the MASA
	voucher, err := p.requestVoucherFromRegistrar(domainCerts)
	if err != nil {
		p.logger.Errorf("Failed to request voucher from local registrar: %v", err)
		http.Error(w, "Failed to request voucher from local registrar", http.StatusInternalServerError)
		return
	}

	// Step 3: Update BRSKI state
	p.brskiState.VoucherReceived = true
	p.brskiState.Status = "voucher_received"
	p.brskiState.LastActivity = time.Now()

	// Step 4: Enroll with local registrar using the EST client
	err = p.enrollWithEST()
	if err != nil {
		p.logger.Errorf("Failed to enroll with local registrar: %v", err)
		http.Error(w, "Failed to enroll with local registrar", http.StatusInternalServerError)
		return
	}

	// Step 5: Update final state
	p.brskiState.Enrolled = true
	p.brskiState.Status = "enrolled"
	p.brskiState.LastActivity = time.Now()

	// Return success response
	response := map[string]any{
		"status":        "success",
		"serial_number": p.serialNumber,
		"voucher":       voucher,
		"enrolled":      true,
		"note":          "Pledge is air-gapped and only communicates with local registrar",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	p.logger.Infof("BRSKI enrollment completed successfully for pledge %s via local registrar", p.serialNumber)
}

// handleEnroll handles manual enrollment requests
func (p *MockPledge) handleEnroll(w http.ResponseWriter, r *http.Request) {
	err := p.enrollWithEST()
	if err != nil {
		p.logger.Errorf("Failed to enroll with local registrar: %v", err)
		http.Error(w, "Failed to enroll with local registrar", http.StatusInternalServerError)
		return
	}

	p.brskiState.Enrolled = true
	p.brskiState.Status = "enrolled"
	p.brskiState.LastActivity = time.Now()

	response := map[string]any{
		"status":   "success",
		"enrolled": true,
		"note":     "Enrolled via local registrar (air-gapped pledge)",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// getDomainCertificate retrieves the domain certificate from local registrar using the EST client
func (p *MockPledge) getDomainCertificate() ([]*x509.Certificate, error) {
	ctx := context.Background()

	// Use the EST client to get CA certificates from the local registrar
	// The pledge is air-gapped and can only reach the local registrar
	certs, err := p.estClient.CACerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificates from local registrar: %w", err)
	}

	p.logger.Infof("Retrieved %d CA certificates from local registrar", len(certs))
	return certs, nil
}

// requestVoucherFromRegistrar requests a voucher from the local registrar
// The registrar will proxy the request to the MASA (the pledge cannot reach MASA directly)
func (p *MockPledge) requestVoucherFromRegistrar(domainCerts []*x509.Certificate) (*voucher.Voucher, error) {
	// Create voucher request using the voucher package
	voucherReq := &voucher.VoucherRequest{
		SerialNumber:  voucher.SerialNumber(p.serialNumber),
		Nonce:         fmt.Sprintf("nonce-%d", time.Now().Unix()),
		AssertionInfo: voucher.AssertionVerified,
		CreatedOn:     time.Now(),
	}

	// If we have domain certificates, use the first one as the proximity registrar cert
	if len(domainCerts) > 0 {
		voucherReq.ProximityRegistrarCert = domainCerts[0].Raw
	}

	// Encode the voucher request to JSON
	requestBody, err := voucher.EncodeVoucherRequest(voucherReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encode voucher request: %w", err)
	}

	// Create HTTP client that skips TLS verification for testing
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{p.cert.Raw},
						PrivateKey:  p.privateKey,
					},
				},
			},
		},
	}

	// Make request to the registrar's BRSKI requestvoucher endpoint
	// This is the actual endpoint implemented in the EST server
	requestURL := "https://localhost:8443/.well-known/brski/requestvoucher"

	p.logger.Infof("Sending voucher request to local registrar BRSKI endpoint: %s", requestURL)

	req, err := http.NewRequest("POST", requestURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create voucher request: %w", err)
	}

	// Set the appropriate headers for BRSKI voucher request
	// The EST server expects JSON input and returns JSON output
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send voucher request to registrar: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read voucher response: %w", err)
	}

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registrar returned error status: %d, body: %s", resp.StatusCode, respBody)
	}

	// Decode the voucher from the response
	v, err := voucher.DecodeVoucher(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode voucher from registrar: %w", err)
	}

	p.logger.Infof("Successfully received voucher from local registrar for serial number: %s", string(v.SerialNumber))
	p.logger.Infof("Note: Registrar proxied this request to MASA and returned the response")
	return v, nil
}

// enrollWithEST enrolls with the local registrar using the EST client
func (p *MockPledge) enrollWithEST() error {
	ctx := context.Background()

	// Generate CSR
	csr, err := p.generateCSR()
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Parse the CSR bytes into a CertificateRequest
	certReq, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Use the EST client to enroll with the local registrar
	// The pledge is air-gapped and can only reach the local registrar
	cert, err := p.estClient.Enroll(ctx, certReq)
	if err != nil {
		return fmt.Errorf("failed to enroll with local registrar: %w", err)
	}

	// Store the enrollment certificate
	p.brskiState.EnrollmentCert = cert
	p.brskiState.EnrollmentKey = p.privateKey

	// Save the enrollment certificate to a file
	certFile, err := os.Create("enrollment_cert.pem")
	if err != nil {
		p.logger.Errorf("Failed to create enrollment certificate file: %v", err)
	}
	defer certFile.Close()
	certFile.Write(cert.Raw)

	p.logger.Infof("Successfully enrolled with local registrar, received certificate for: %s", cert.Subject.CommonName)
	return nil
}

// generateCSR generates a certificate signing request
func (p *MockPledge) generateCSR() ([]byte, error) {
	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:  []string{"Mock Pledge Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"456 Pledge Street"},
			PostalCode:    []string{"94105"},
			CommonName:    "pledge1",
		},
		DNSNames:    []string{"pledge1.example.com", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, p.privateKey)
	if err != nil {
		return nil, err
	}

	return csrDER, nil
}
