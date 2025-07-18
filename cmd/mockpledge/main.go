package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

// VoucherRequest represents a voucher request to MASA
type VoucherRequest struct {
	SerialNumber string `json:"serial-number"`
	DomainCert   string `json:"domain-cert"`
	Nonce        string `json:"nonce"`
	Assertion    string `json:"assertion"`
}

// VoucherResponse represents a voucher response from MASA
type VoucherResponse struct {
	Voucher *Voucher `json:"voucher"`
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

// EnrollmentRequest represents an enrollment request to EST server
type EnrollmentRequest struct {
	CSR string `json:"csr"`
}

// EnrollmentResponse represents an enrollment response from EST server
type EnrollmentResponse struct {
	Certificate string `json:"certificate"`
}

func main() {
	// Create pledge certificate
	cert, privateKey, err := createPledgeCertificate()
	if err != nil {
		log.Fatalf("Failed to create pledge certificate: %v", err)
	}

	// Generate unique serial number
	serialNumber := fmt.Sprintf("PLEDGE-%d", time.Now().Unix())

	// Create mock pledge
	pledge := &MockPledge{
		privateKey:   privateKey,
		cert:         cert,
		serialNumber: serialNumber,
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
	log.Printf("Starting BRSKI voucher request for pledge %s", p.serialNumber)

	// Step 1: Discover EST server (in real implementation, this would be via mDNS or DHCP)
	estServerURL := "https://localhost:8443"
	masaURL := "https://localhost:8444"

	// Step 2: Get domain certificate from EST server
	domainCert, err := p.getDomainCertificate(estServerURL)
	if err != nil {
		log.Printf("Failed to get domain certificate: %v", err)
		http.Error(w, "Failed to get domain certificate", http.StatusInternalServerError)
		return
	}

	// Step 3: Request voucher from MASA
	voucher, err := p.requestVoucherFromMASA(masaURL, domainCert)
	if err != nil {
		log.Printf("Failed to request voucher from MASA: %v", err)
		http.Error(w, "Failed to request voucher from MASA", http.StatusInternalServerError)
		return
	}

	// Step 4: Update BRSKI state
	p.brskiState.VoucherReceived = true
	p.brskiState.Status = "voucher_received"
	p.brskiState.LastActivity = time.Now()

	// Step 5: Enroll with EST server
	err = p.enrollWithEST(estServerURL)
	if err != nil {
		log.Printf("Failed to enroll with EST server: %v", err)
		http.Error(w, "Failed to enroll with EST server", http.StatusInternalServerError)
		return
	}

	// Step 6: Update final state
	p.brskiState.Enrolled = true
	p.brskiState.Status = "enrolled"
	p.brskiState.LastActivity = time.Now()

	// Return success response
	response := map[string]any{
		"status":        "success",
		"serial_number": p.serialNumber,
		"voucher":       voucher,
		"enrolled":      true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	log.Printf("BRSKI enrollment completed successfully for pledge %s", p.serialNumber)
}

// handleEnroll handles manual enrollment requests
func (p *MockPledge) handleEnroll(w http.ResponseWriter, r *http.Request) {
	estServerURL := "https://localhost:8443"

	err := p.enrollWithEST(estServerURL)
	if err != nil {
		log.Printf("Failed to enroll with EST server: %v", err)
		http.Error(w, "Failed to enroll with EST server", http.StatusInternalServerError)
		return
	}

	p.brskiState.Enrolled = true
	p.brskiState.Status = "enrolled"
	p.brskiState.LastActivity = time.Now()

	response := map[string]any{
		"status":   "success",
		"enrolled": true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// getDomainCertificate retrieves the domain certificate from EST server
func (p *MockPledge) getDomainCertificate(estServerURL string) (string, error) {
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

	// Request CA certificates from EST server
	resp, err := client.Get(estServerURL + "/.well-known/est/cacerts")
	if err != nil {
		return "", fmt.Errorf("failed to get CA certificates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("EST server returned status: %d", resp.StatusCode)
	}

	// For simplicity, we'll return a placeholder domain certificate
	// In a real implementation, you would parse the PKCS#7 response
	return "-----BEGIN CERTIFICATE-----\nMOCK_DOMAIN_CERT\n-----END CERTIFICATE-----", nil
}

// requestVoucherFromMASA requests a voucher from the MASA
func (p *MockPledge) requestVoucherFromMASA(masaURL, domainCert string) (*Voucher, error) {
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

	// Create voucher request
	voucherReq := VoucherRequest{
		SerialNumber: p.serialNumber,
		DomainCert:   domainCert,
		Nonce:        fmt.Sprintf("nonce-%d", time.Now().Unix()),
		Assertion:    "verified",
	}

	// Convert request to JSON
	reqBody, err := json.Marshal(voucherReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal voucher request: %w", err)
	}

	// Send request to MASA
	resp, err := client.Post(masaURL+"/.well-known/brski/requestvoucher", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send voucher request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MASA returned status: %d", resp.StatusCode)
	}

	// Parse response
	var voucherResp VoucherResponse
	if err := json.NewDecoder(resp.Body).Decode(&voucherResp); err != nil {
		return nil, fmt.Errorf("failed to decode voucher response: %w", err)
	}

	return voucherResp.Voucher, nil
}

// enrollWithEST enrolls with the EST server
func (p *MockPledge) enrollWithEST(estServerURL string) error {
	// Create HTTP client with mTLS configuration
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

	// Generate CSR
	csr, err := p.generateCSR()
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Encode CSR in base64
	csrBase64 := base64.StdEncoding.EncodeToString(csr)

	// Note: EST expects PKCS#10 CSR in base64 format, not JSON

	// Send enrollment request with proper EST headers
	req, err := http.NewRequest("POST", estServerURL+"/.well-known/est/simpleenroll", bytes.NewReader([]byte(csrBase64)))
	if err != nil {
		return fmt.Errorf("failed to create enrollment request: %w", err)
	}

	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send enrollment request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EST server returned status: %d", resp.StatusCode)
	}

	log.Printf("Successfully enrolled with EST server")
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
