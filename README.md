# KRITS3M EST

This EST (Enrollment over Secure Transport) project provides a Go
implementation of the EST protocol, with PQ (Post-Quantum) support built on top
of the KRITIS3M ASL Library.

## Prerequisites

To build the EST server, you need to have the following software installed:

- Go 1.23 or later
- [KRITIS3M ASL Library](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_asl/)
- [KRITIS3M PKI Library](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_pki/)

## Installation

To install the EST server/client you have 3 options.

The first option does not require installing the Go toolchain, but it requires
the KRITIS3M ASL Library to be installed.

- Download the latest release from the [releases page](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/releases).

- Clone the repository and build the server from source:

```bash
git clone https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est.git
cd est
go build -o estserver cmd/estserver
```

- Use the `go install` command:

```bash
go install github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/cmd/estserver@latest
```

## Usage

### Server

Best is to create a configuration file for the server. An example configuration
file looks like this:

```json
{
  "ca": {
    "certificates": "<path-to-ca-cert>",
    "private_key": "<path-to-ca-private-key>"
  },
  "tls": {
    "listen_address": ":8443",
    "certificates": "<path-to-server-cert>",
    "private_key": "<path-to-server-private-key>",
    "client_cas": [
      "<path-to-client-ca-certs>"
    ]
  },
  "endpoint": {
    "mutual_authentication": true,
    "no_encryption": false,
    "asl_key_exchange_method": 0,
    "hybrid_signature_mode": 0,
    "keylog_file": "/tmp/keylog.txt"
  },
  "asl_config": {
    "logging_enabled": true,
    "log_level": 3,
    "secure_element_log_support": false
  },
  "allowed_hosts": [
    "localhost",
    "127.0.0.1",
    "[::1]"
  ],
  "healthcheck_password": "xyzzy",
  "rate_limit": 150,
  "timeout": 30
}
```

```bash
estserver -config config.json
```

### Client

The client can be used to enroll a device with the EST server:

!!! warning
    Use the same values in the certificate you use for the mtls connection.

```bash
estclient csr \
    -key <path-to-client-key> \
    -cn "<value>" \
    -country "<value>" \
    -org "<value>" \
    -ou "<value>" \
    -emails "<value>" \
    -dnsnames "localhost" \
    -out csr.pem -ips 127.0.0.1
```

```bash
estclient enroll \
    -server localhost:8443 \
    -explicit <path-to-ca-cert> \
    -csr csr.pem \
    -ca <path-to-ca-cert> \
    -cert <path-to-client-cert> \
    -key <path-to-client-key>
```
