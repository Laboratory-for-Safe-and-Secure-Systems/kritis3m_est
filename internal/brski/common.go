package brski

import (
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/types"
)

// Re-export types from the types package
var (
	// Endpoints
	RequestVoucherEndpoint         = types.RequestVoucherEndpoint
	VoucherStatusEndpoint          = types.VoucherStatusEndpoint
	RegistrarVoucherEndpoint       = types.RegistrarVoucherEndpoint
	RegistrarVoucherStatusEndpoint = types.RegistrarVoucherStatusEndpoint
	RequestAuditLogEndpoint        = types.RequestAuditLogEndpoint

	// Error codes
	ErrInvalidRequest            = types.ErrInvalidRequest
	ErrUnauthorized              = types.ErrUnauthorized
	ErrForbidden                 = types.ErrForbidden
	ErrNotFound                  = types.ErrNotFound
	ErrInternalServerError       = types.ErrInternalServerError
	ErrMASAUnavailable           = types.ErrMASAUnavailable
	ErrVoucherVerificationFailed = types.ErrVoucherVerificationFailed
	ErrInvalidVoucher            = types.ErrInvalidVoucher
	ErrDeviceNotAccepted         = types.ErrDeviceNotAccepted
)

// PledgeState represents pledge states
type PledgeState = types.PledgeState

// Re-export pledge states
const (
	StateUninitialized     = types.StateUninitialized
	StateDiscovering       = types.StateDiscovering
	StateRequestingVoucher = types.StateRequestingVoucher
	StateValidatingVoucher = types.StateValidatingVoucher
	StateImprinting        = types.StateImprinting
	StateEnrolling         = types.StateEnrolling
	StateBootstrapped      = types.StateBootstrapped
	StateFailed            = types.StateFailed
)

// RegistrarConfig represents a registrar configuration
type RegistrarConfig = types.RegistrarConfig

// Error represents a BRSKI error
type Error = types.Error
