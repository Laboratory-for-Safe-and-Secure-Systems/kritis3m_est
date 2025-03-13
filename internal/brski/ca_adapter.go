// Package brski provides an implementation of the Bootstrapping Remote Secure Key
// Infrastructure (BRSKI) protocol.
package brski

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/registrar"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/types"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/voucher"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
)

// estError is a wrapper for est.Error
type estError struct {
	status     int
	desc       string
	retryAfter int
}

// StatusCode returns the HTTP status code.
func (e *estError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e *estError) Error() string {
	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e *estError) RetryAfter() int {
	return e.retryAfter
}

// ESTRegistrar is an implementation of the est.BRSKIRegistrar interface
// that delegates to our existing BRSKI registrar implementation.
type ESTRegistrar struct {
	registrar *registrar.Registrar
	logger    common.Logger
}

// NewESTRegistrar creates a new adapter for the EST server that implements
// the est.BRSKIRegistrar interface using our BRSKI registrar.
func NewESTRegistrar(config *types.RegistrarConfig, domainCA *x509.Certificate) (*ESTRegistrar, error) {
	reg, err := registrar.NewRegistrar(config, domainCA)
	if err != nil {
		return nil, err
	}

	return &ESTRegistrar{
		registrar: reg,
		logger:    config.Logger,
	}, nil
}

// GetRegistrar returns the underlying BRSKI registrar
func (e *ESTRegistrar) GetRegistrar() *registrar.Registrar {
	return e.registrar
}

// ProcessVoucherRequest processes a voucher request from a pledge and returns a voucher.
func (e *ESTRegistrar) ProcessVoucherRequest(ctx context.Context, voucherRequestBytes []byte, aps string, r *http.Request) ([]byte, error) {
	e.logger.Debugf("Processing voucher request, aps: %s", aps)

	// Decode the voucher request
	vr, err := voucher.DecodeVoucherRequest(voucherRequestBytes)
	if err != nil {
		return nil, &estError{
			status: http.StatusBadRequest,
			desc:   "Failed to decode voucher request",
		}
	}

	// Process the voucher request
	v, err := e.registrar.ProcessVoucherRequest(vr)
	if err != nil {
		// Check if it's a BRSKI error and convert to EST error
		if brskiErr, ok := err.(*types.Error); ok {
			return nil, &estError{
				status: brskiErr.Code,
				desc:   brskiErr.Message,
			}
		}

		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to process voucher request: " + err.Error(),
		}
	}

	// Encode the voucher
	voucherBytes, err := voucher.EncodeVoucher(v)
	if err != nil {
		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to encode voucher",
		}
	}

	return voucherBytes, nil
}

// ProcessVoucherStatus processes a voucher status update from a pledge.
func (e *ESTRegistrar) ProcessVoucherStatus(ctx context.Context, serialNumber string, statusBytes []byte, aps string, r *http.Request) error {
	e.logger.Debugf("Processing voucher status, aps: %s, serialNumber: %s", aps, serialNumber)

	// Decode the voucher status
	vs, err := voucher.DecodeVoucherStatus(statusBytes)
	if err != nil {
		return &estError{
			status: http.StatusBadRequest,
			desc:   "Failed to decode voucher status",
		}
	}

	// Process the voucher status
	err = e.registrar.ProcessVoucherStatus(voucher.SerialNumber(serialNumber), vs)
	if err != nil {
		// Check if it's a BRSKI error and convert to EST error
		if brskiErr, ok := err.(*types.Error); ok {
			return &estError{
				status: brskiErr.Code,
				desc:   brskiErr.Message,
			}
		}

		return &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to process voucher status: " + err.Error(),
		}
	}

	return nil
}

// GetVoucher retrieves a cached voucher for a device.
func (e *ESTRegistrar) GetVoucher(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	e.logger.Debugf("Getting voucher, aps: %s, serialNumber: %s", aps, serialNumber)

	// Get the voucher
	v, err := e.registrar.GetVoucher(voucher.SerialNumber(serialNumber))
	if err != nil {
		// Check if it's a BRSKI error and convert to EST error
		if brskiErr, ok := err.(*types.Error); ok {
			return nil, &estError{
				status: brskiErr.Code,
				desc:   brskiErr.Message,
			}
		}

		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to get voucher: " + err.Error(),
		}
	}

	// Encode the voucher
	voucherBytes, err := voucher.EncodeVoucher(v)
	if err != nil {
		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to encode voucher",
		}
	}

	return voucherBytes, nil
}

// GetVoucherStatus retrieves the status of a voucher.
func (e *ESTRegistrar) GetVoucherStatus(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	e.logger.Debugf("Getting voucher status, aps: %s, serialNumber: %s", aps, serialNumber)

	// Since our implementation doesn't have a direct GetVoucherStatus method,
	// we'll create a simple status response based on whether the voucher exists
	_, err := e.registrar.GetVoucher(voucher.SerialNumber(serialNumber))

	var status *voucher.VoucherStatus
	if err != nil {
		if brskiErr, ok := err.(*types.Error); ok && brskiErr.Code == types.ErrNotFound {
			status = &voucher.VoucherStatus{
				Status: "not_found",
				Reason: "No voucher found for the device",
			}
		} else {
			return nil, &estError{
				status: http.StatusInternalServerError,
				desc:   "Failed to check voucher status",
			}
		}
	} else {
		status = &voucher.VoucherStatus{
			Status: "valid",
			Reason: "Voucher is valid",
		}
	}

	// Encode the status
	statusBytes, err := voucher.EncodeVoucherStatus(status)
	if err != nil {
		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to encode voucher status",
		}
	}

	return statusBytes, nil
}

// GetAuditLog retrieves the audit log for a device from the MASA.
func (e *ESTRegistrar) GetAuditLog(ctx context.Context, serialNumber string, aps string, r *http.Request) ([]byte, error) {
	e.logger.Debugf("Getting audit log, aps: %s, serialNumber: %s", aps, serialNumber)

	// Get the audit log
	entries, err := e.registrar.GetAuditLog(voucher.SerialNumber(serialNumber))
	if err != nil {
		// Check if it's a BRSKI error and convert to EST error
		if brskiErr, ok := err.(*types.Error); ok {
			return nil, &estError{
				status: brskiErr.Code,
				desc:   brskiErr.Message,
			}
		}

		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to get audit log: " + err.Error(),
		}
	}

	// Since our GetAuditLog returns objects, we need to convert them to JSON
	// This example implementation just assumes an empty log if no entries are found
	if len(entries) == 0 {
		return []byte("[]"), nil
	}

	// Convert to JSON
	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return nil, &estError{
			status: http.StatusInternalServerError,
			desc:   "Failed to encode audit log",
		}
	}

	return jsonBytes, nil
}
