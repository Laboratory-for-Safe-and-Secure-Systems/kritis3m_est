package masa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	aslClient "github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/listener"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/logging"
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

	// Certificate settings for ASL
	MASACertPath string
}

// NewClient creates a new MASA client with ASL support
// The masaCert parameter is the path to the MASA's CA certificate
func NewClient(baseURL *url.URL, masaCertPath string, logger common.Logger) (*Client, error) {
	client := &Client{
		BaseURL:      baseURL,
		Logger:       logger,
		MASACertPath: masaCertPath,
	}

	// Create HTTP client with ASL transport
	httpClient, err := client.initASLClient()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ASL client: %w", err)
	}
	client.HTTPClient = httpClient

	return client, nil
}

// initASLClient initializes an HTTP client with ASL transport for BRSKI communications
func (c *Client) initASLClient() (*http.Client, error) {
	// Per RFC 8995, section 5.1, the registrar acts as a client to the MASA
	// and uses TLS to authenticate the MASA using the MASA's trust anchor

	// Create endpoint configuration for ASL
	config := &asl.EndpointConfig{
		// Per RFC 8995, mutual authentication is not required for the MASA client
		// The registrar authenticates the MASA server, but the MASA doesn't need to authenticate the registrar
		MutualAuthentication: false,
		ASLKeyExchangeMethod: 0,
		Ciphersuites:         []string{},
		PreSharedKey: asl.PreSharedKey{
			Enable: false,
		},
		// Include the MASA's CA certificate as the root certificate
		RootCertificates: asl.RootCertificates{
			Paths: []string{c.MASACertPath},
		},
	}

	// Initialize ASL endpoint
	endpoint := asl.ASLsetupClientEndpoint(config)
	if endpoint == nil {
		return nil, fmt.Errorf("failed to setup ASL endpoint")
	}

	// Create ASL transport
	aslTransport := &aslClient.ASLTransport{
		Endpoint: endpoint,
		Dialer:   &net.Dialer{Timeout: 30 * time.Second},
		Logger:   logging.NewLogger(log.Default()),
	}

	// Return configured HTTP client
	return &http.Client{
		Transport: aslTransport,
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
