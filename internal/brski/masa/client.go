package masa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/voucher"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
)

// Client represents a MASA client
type Client struct {
	// BaseURL is the base URL of the MASA server
	BaseURL *url.URL

	// HTTPClient is the HTTP client to use for requests
	HTTPClient *http.Client

	// Logger is the logger to use
	Logger common.Logger
}

// NewClient creates a new MASA client with standard TLS support
// The masaCertPaths parameter is a slice of paths to the MASA's CA certificates
func NewClient(baseURL *url.URL, masaCertPaths []string, logger common.Logger) (*Client, error) {
	client := &Client{
		BaseURL: baseURL,
		Logger:  logger,
	}

	// Create HTTP client with TLS transport
	httpClient, err := client.initTLSClient(masaCertPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TLS client: %w", err)
	}
	client.HTTPClient = httpClient

	return client, nil
}

// initTLSClient initializes an HTTP client with TLS transport for BRSKI communications
func (c *Client) initTLSClient(masaCertPaths []string) (*http.Client, error) {
	// Create a certificate pool for the MASA certificates
	caCertPool := x509.NewCertPool()

	// Load MASA certificates
	for _, certPath := range masaCertPaths {
		if certPath == "" {
			continue
		}

		certData, err := os.ReadFile(certPath)
		if err != nil {
			c.Logger.Infof("Failed to read MASA certificate %s: %v", certPath, err)
			continue
		}

		if !caCertPool.AppendCertsFromPEM(certData) {
			c.Logger.Infof("Failed to parse MASA certificate %s", certPath)
		}
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: len(masaCertPaths) == 0, // Skip verification if no certs provided
	}

	// Create transport with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Return configured HTTP client
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// RequestVoucher sends a voucher request to the MASA and returns the voucher
func (c *Client) RequestVoucher(voucherRequest *voucher.VoucherRequest) (*voucher.Voucher, error) {
	// Encode the voucher request
	requestBody, err := voucher.EncodeVoucherRequest(voucherRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode voucher request: %w", err)
	}

	// Create a request to the MASA voucher endpoint
	requestURL := c.BaseURL.JoinPath("/requestvoucher")
	req, err := http.NewRequest(http.MethodPost, requestURL.String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the appropriate headers
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("Accept", "application/jose+json")

	// Send the request
	c.Logger.Debugf("Sending voucher request to MASA: %s", requestURL.String())
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MASA returned error status: %d, body: %s", resp.StatusCode, respBody)
	}

	// Decode the voucher
	v, err := voucher.DecodeVoucher(respBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode voucher: %w", err)
	}

	return v, nil
}

// RequestAuditLog requests the audit log for a serial number from the MASA
func (c *Client) RequestAuditLog(serialNumber voucher.SerialNumber) ([]*voucher.AuditLogEntry, error) {
	// Create a request to the MASA audit log endpoint
	requestURL := c.BaseURL.JoinPath("/requestauditlog")

	// Add the serial number as a query parameter
	query := requestURL.Query()
	query.Set("serial-number", string(serialNumber))
	requestURL.RawQuery = query.Encode()

	// Create the request
	req, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the appropriate headers - per RFC 8995 section 5.8
	req.Header.Set("Accept", "application/json")

	// Send the request
	c.Logger.Debugf("Requesting audit log from MASA: %s", requestURL.String())
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MASA returned error status: %d, body: %s", resp.StatusCode, respBody)
	}

	// Decode the audit log entries
	var entries []*voucher.AuditLogEntry
	err = json.Unmarshal(respBody, &entries)
	if err != nil {
		return nil, fmt.Errorf("failed to decode audit log entries: %w", err)
	}

	return entries, nil
}
