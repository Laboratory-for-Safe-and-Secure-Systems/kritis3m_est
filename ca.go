package est

import (
	"context"
	"crypto/x509"
	"net/http"
)

// CA is a Certificate Authority backing an EST server. The server can be
// connected to any backing CA by providing an implementation of this interface.
//
// All operations receive:
// - a context, from which the EST server logger can be retrieved by calling
//   LoggerFromContext
// - the optional URI additional path segment (RFC7030 3.2.2)
// - the HTTP request object from the server, from which the HTTP headers
//   passed by the client (including the Host header, to support virtual
//   servers) can be obtained
//
// Any error object returned from these functions which implements Error will be
// used by the EST server to determine the HTTP response code, human-readable
// error description, and Retry-After header value, if applicable. Any other
// error will be treated as an internal server error.
type CA interface {
	// CACerts requests a copy of the current CA certificates. See RFC7030 4.1.
	CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error)

	// CSRAttrs requests a list of CA-desired CSR attributes. The returned list
	// may be empty. See RFC7030 4.5.
	CSRAttrs(ctx context.Context, aps string, r *http.Request) (CSRAttrs, error)

	// Enroll requests a new certificate. See RFC7030 4.2.
	Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error)

	// Reenroll requests renewal/rekey of an existing certificate. See RFC7030
	// 4.2.
	Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error)

	// ServerKeyGen requests a new certificate and a private key. The key must
	// be returned as a DER-encoded PKCS8 PrivateKeyInfo structure if additional
	// encryption is not being employed, or returned inside a CMS SignedData
	// structure which itself is inside a CMS EnvelopedData structure. See
	// RFC7030 4.4.
	ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error)

  // Revokation List
  RevocationList(ctx context.Context, r *http.Request) ([]byte, error)
}

// Error represents an error which can be translated into an HTTP
// status code and message, and optionally specify a Retry-After period.
type Error interface {
	// StatusCode returns the HTTP status code.
	StatusCode() int

	// Error returns a human-readable description of the error.
	Error() string

	// RetryAfter returns the value in seconds after which the client should
	// retry the request.
	RetryAfter() int
}
