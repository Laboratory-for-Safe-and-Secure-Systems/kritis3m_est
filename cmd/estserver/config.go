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
