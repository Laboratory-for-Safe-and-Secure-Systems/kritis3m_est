package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// config contains the EST server configuration.
type config struct {
	RealCA              *realCAConfig `json:"ca,omitempty"`
	TLS                 *tlsConfig    `json:"tls,omitempty"`
	AllowedHosts        []string      `json:"allowed_hosts,omitempty"`
	HealthCheckPassword string        `json:"healthcheck_password"`
	RateLimit           int           `json:"rate_limit"`
	Timeout             int           `json:"timeout"`
	Logfile             string        `json:"log_file"`
	LogLevel            int           `json:"log_level"`
}

type PKCS11Module struct {
	Path string `json:"path"`
	Slot int    `json:"slot,omitempty"`
	Pin  string `json:"pin"`
}

// RealCAConfig contains the real CA configuration.
type realCAConfig struct {
	Certs        string        `json:"certificates"`
	Key          string        `json:"private_key"`
	IssuerModule *PKCS11Module `json:"pkcs11_module,omitempty"`
}

// tlsConfig contains the server's TLS configuration.
type tlsConfig struct {
	ListenAddr   string             `json:"listen_address"`
	Certs        string             `json:"certificates"`
	Key          string             `json:"private_key"`
	ClientCAs    []string           `json:"client_cas,omitempty"`
	ASLEndpoint  *aslEndpointConfig `json:"asl_endpoint,omitempty"`
	EntityModule *PKCS11Module      `json:"pkcs11_module,omitempty"`
}

// EndpointConfig contains the configuration for an EST endpoint.
type aslEndpointConfig struct {
	MutualAuthentication bool     `json:"mutual_authentication,omitempty"`
	Ciphersuites         []string `json:"ciphersuites,omitempty"`
	ASLKeyExchangeMethod int      `json:"key_exchange_method,omitempty"`
	KeylogFile           string   `json:"keylog_file,omitempty"`
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
        "private_key": "/path/to/CA/private/key.pem",
        "pkcs11_module": {
            "path": "/usr/lib/softhsm/libsofthsm2.so",
            "slot": 0,
            "pin": "1234"
        }
    },
    "tls": {
        "listen_address": "localhost:8443",
        "certificates": "/path/to/server/certificates.pem",
        "private_key": "/path/to/server/private/key.pem",
        "client_cas": [
            "/path/to/first/client/CA/root/certificate.pem",
            "/path/to/second/client/CA/root/certificate.pem",
            "/path/to/third/client/CA/root/certificate.pem"
        ],
	"asl_endpoint": {
		"mutual_authentication": true,
		"ciphersuites": ["TLS13-AES256-GCM-SHA384", "TLS13-CHACHA20-POLY1305-SHA256"],
		"key_exchange_method": 0,
		"keylog_file": "/path/to/keylog/file.txt"
	},
	"pkcs11_module": {
            "path": "/usr/lib/softhsm/libsofthsm2.so",
            "slot": 0,
            "pin": "1234"
        }
    },
    "allowed_hosts": [
        "localhost",
        "127.0.0.1",
        "[::1]"
    ],
    "healthcheck_password": "xyzzy",
    "rate_limit": 150,
    "timeout": 30,
    "log_file": "/path/to/log.file",
    "log_level": 3
}`

// sampleConfig outputs a sample configuration file.
func sampleConfig() {
	fmt.Println(sample)
}
