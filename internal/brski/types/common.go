package types

import (
	"fmt"
	"net/url"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
)

// Well-known BRSKI endpoints as defined in RFC 8995
const (
	RequestVoucherEndpoint         = "/.well-known/brski/requestvoucher"
	VoucherStatusEndpoint          = "/.well-known/brski/voucher_status"
	RegistrarVoucherEndpoint       = "/.well-known/brski/registrar/voucher"
	RegistrarVoucherStatusEndpoint = "/.well-known/brski/registrar/voucher_status"
	RequestAuditLogEndpoint        = "/.well-known/est/requestauditlog"
)

// VoucherFormat represents the format of the voucher (JSON or CBOR)
type VoucherFormat string

// Supported voucher formats
const (
	JSONFormat VoucherFormat = "json"
	// CBORFormat VoucherFormat = "cbor"
)

// PledgeState represents the different states a pledge can be in during the bootstrapping process
type PledgeState string

// Pledge states
const (
	StateUninitialized     PledgeState = "uninitialized"
	StateDiscovering       PledgeState = "discovering"
	StateRequestingVoucher PledgeState = "requesting_voucher"
	StateValidatingVoucher PledgeState = "validating_voucher"
	StateImprinting        PledgeState = "imprinting"
	StateEnrolling         PledgeState = "enrolling"
	StateBootstrapped      PledgeState = "bootstrapped"
	StateFailed            PledgeState = "failed"
)

// RegistrarConfig contains configuration options for the BRSKI registrar
type RegistrarConfig struct {
	// MASAURLs is a map of manufacturer domain to MASA URL
	MASAURLs map[string]*url.URL

	// MASACerts is a map of manufacturer domain to trusted MASA certificates
	MASACerts map[string][]string

	// DomainName is the domain name of the registrar
	DomainName string

	// RequireVoucherVerification indicates if voucher verification is required
	RequireVoucherVerification bool

	// AcceptedDeviceSerialNumbers is an optional whitelist of serial numbers that are allowed to register
	AcceptedDeviceSerialNumbers []string

	// VoucherCacheDir is the directory to cache vouchers
	VoucherCacheDir string

	// VoucherValidityPeriod is the period of time a voucher is considered valid
	VoucherValidityPeriod time.Duration

	// Logger is the logger to use
	Logger common.Logger
}

// Error represents a BRSKI-specific error
type Error struct {
	Code    int
	Message string
	Err     error
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("BRSKI error %d: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("BRSKI error %d: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Err
}

// BRSKI error codes
const (
	ErrInvalidRequest            = 400
	ErrUnauthorized              = 401
	ErrForbidden                 = 403
	ErrNotFound                  = 404
	ErrInternalServerError       = 500
	ErrMASAUnavailable           = 503
	ErrVoucherVerificationFailed = 4001
	ErrInvalidVoucher            = 4002
	ErrDeviceNotAccepted         = 4003
)
