package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// config contains the EST server configuration.
type config struct {
	RealCA              *realCAConfig   `json:"ca,omitempty"`
	TLS                 *tlsConfig      `json:"tls,omitempty"`
	Endpoint            *endpointConfig `json:"endpoint,omitempty"`
	ASLConfig           *aslConfig      `json:"asl_config,omitempty"`
	AllowedHosts        []string        `json:"allowed_hosts,omitempty"`
	HealthCheckPassword string          `json:"healthcheck_password"`
	RateLimit           int             `json:"rate_limit"`
	Timeout             int             `json:"timeout"`
	Logfile             string          `json:"log_file"`
}

// RealCAConfig contains the real CA configuration.
type realCAConfig struct {
	Certs string `json:"certificates"`
	Key   string `json:"private_key"`
}

// tlsConfig contains the server's TLS configuration.
type tlsConfig struct {
	ListenAddr string   `json:"listen_address"`
	Certs      string   `json:"certificates"`
	Key        string   `json:"private_key"`
	ClientCAs  []string `json:"client_cas,omitempty"`
}

// EndpointConfig contains the configuration for an EST endpoint.
type endpointConfig struct {
	MutualAuthentication    bool   `json:"mutual_authentication"`
	NoEncryption            bool   `json:"no_encryption"`
	UseSecureElement        bool   `json:"use_secure_element"`
	SecureElementImportKeys bool   `json:"secure_element_import_keys"`
	HybridSignatureMode     int    `json:"hybrid_signature_mode"`
	KeylogFile              string `json:"keylog_file"`
}

// aslConfig contains the configuration for the ASL library.
type aslConfig struct {
	LoggingEnabled       bool `json:"logging_enabled"`
	LogLevel             int  `json:"log_level"`
	SecureElementSupport bool `json:"secure_element_support"`
}

// configFromFile returns a new EST server configuration from a JSON-encoded
// configuration file.
func configFromFile(filename string) (*config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

const sample = `{
    "ca": {
        "certificates": "/path/to/CA/certificates.pem",
        "private_key": "/path/to/CA/private/key.pem"
    },
    "tls": {
        "listen_address": "localhost:8443",
        "certificates": "/path/to/server/certificates.pem",
        "private_key": "/path/to/server/private/key.pem",
        "client_cas": [
            "/path/to/first/client/CA/root/certificate.pem",
            "/path/to/second/client/CA/root/certificate.pem",
            "/path/to/third/client/CA/root/certificate.pem"
        ]
    },
    "endpoint": {
        "mutual_authentication": true,
        "no_encryption": false,
        "use_secure_element": false,
        "secure_element_import_keys": false,
        "hybrid_signature_mode": 3,
        "keylog_file": "/path/to/keylog/file.txt"
    },
    "asl_config": {
      logging_enabled: true,
      log_level: 3,
      secure_element_support: false
    },
    "allowed_hosts": [
        "localhost",
        "127.0.0.1",
        "[::1]"
    ],
    "healthcheck_password": "xyzzy",
    "rate_limit": 150,
    "timeout": 30,
    "log_file": "/path/to/log.file"
}`

// sampleConfig outputs a sample configuration file.
func sampleConfig() {
	fmt.Println(sample)
}
