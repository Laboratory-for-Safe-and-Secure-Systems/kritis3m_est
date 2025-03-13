package registrar

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"slices"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/masa"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/types"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/brski/voucher"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
)

// Registrar is the BRSKI registrar implementation
type Registrar struct {
	// Config contains the configuration for the registrar
	Config *types.RegistrarConfig

	// MASAClients is a map of manufacturer domain to MASA client
	MASAClients map[string]*masa.Client

	// DomainCA is the domain's certificate authority
	DomainCA *x509.Certificate

	// VoucherCache is a cache of vouchers, keyed by device serial number
	VoucherCache map[voucher.SerialNumber]*voucher.Voucher

	// voucherCacheMutex is a mutex to protect the voucher cache
	voucherCacheMutex sync.RWMutex

	// Logger is the logger to use
	Logger common.Logger
}

// NewRegistrar creates a new BRSKI registrar
func NewRegistrar(config *types.RegistrarConfig, domainCA *x509.Certificate) (*Registrar, error) {
	// Create the registrar
	r := &Registrar{
		Config:       config,
		MASAClients:  make(map[string]*masa.Client),
		DomainCA:     domainCA,
		VoucherCache: make(map[voucher.SerialNumber]*voucher.Voucher),
		Logger:       config.Logger,
	}

	// Create the MASA clients
	for domain, masaURL := range config.MASAURLs {
		masaCert := config.MASACerts[domain]
		if len(masaCert) == 0 {
			return nil, fmt.Errorf("MASA certificate not found for domain: %s", domain)
		}

		masaClient, err := masa.NewClient(masaURL, masaCert[0], config.Logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create MASA client for domain %s: %w", domain, err)
		}

		r.MASAClients[domain] = masaClient
	}

	// Create the voucher cache directory if it doesn't exist
	if config.VoucherCacheDir != "" {
		err := os.MkdirAll(config.VoucherCacheDir, 0700)
		if err != nil {
			return nil, fmt.Errorf("failed to create voucher cache directory: %w", err)
		}
	}

	return r, nil
}

// ProcessVoucherRequest processes a voucher request from a pledge
func (r *Registrar) ProcessVoucherRequest(req *voucher.VoucherRequest) (*voucher.Voucher, error) {
	r.Logger.Infof("Processing voucher request for serial number: %s", string(req.SerialNumber))

	// Check if the device is in the accepted devices list, if configured
	if len(r.Config.AcceptedDeviceSerialNumbers) > 0 {
		found := slices.Contains(r.Config.AcceptedDeviceSerialNumbers, string(req.SerialNumber))

		if !found {
			return nil, &types.Error{
				Code:    types.ErrDeviceNotAccepted,
				Message: "Device serial number not in accepted list",
			}
		}
	}

	// Check if we have a cached voucher for this device
	r.voucherCacheMutex.RLock()
	cachedVoucher, ok := r.VoucherCache[req.SerialNumber]
	r.voucherCacheMutex.RUnlock()

	if ok {
		// Make sure the voucher hasn't expired
		if cachedVoucher.ExpiresOn.After(time.Now()) {
			r.Logger.Debugf("Using cached voucher for serial number: %s", string(req.SerialNumber))
			return cachedVoucher, nil
		}

		// Remove the expired voucher from the cache
		r.voucherCacheMutex.Lock()
		delete(r.VoucherCache, req.SerialNumber)
		r.voucherCacheMutex.Unlock()
	}

	// Determine the MASA client to use
	// In a real implementation, this would use information from the pledge's IDevID to determine the manufacturer
	// For now, we'll use the MASA client for the domain name
	masaClient := r.MASAClients[r.Config.DomainName]

	if masaClient == nil {
		return nil, &types.Error{
			Code:    types.ErrMASAUnavailable,
			Message: "No MASA client available",
		}
	}

	// Forward the voucher request to the MASA
	// For simplicity, we're forwarding the request as-is, but in a real implementation
	// we might need to modify it or create a new one
	v, err := masaClient.RequestVoucher(req)
	if err != nil {
		return nil, &types.Error{
			Code:    types.ErrMASAUnavailable,
			Message: "Failed to request voucher from MASA",
			Err:     err,
		}
	}

	// Validate the voucher
	if r.Config.RequireVoucherVerification {
		// In a real implementation, this would verify the signature on the voucher
		// and validate that the pinned domain certificate matches our domain CA

		// For now, we'll just check that the serial number matches
		if v.SerialNumber != req.SerialNumber {
			return nil, &types.Error{
				Code:    types.ErrVoucherVerificationFailed,
				Message: "Voucher serial number does not match request",
			}
		}
	}

	// Cache the voucher
	r.voucherCacheMutex.Lock()
	r.VoucherCache[req.SerialNumber] = v
	r.voucherCacheMutex.Unlock()

	// If a voucher cache directory is configured, save the voucher to disk
	if r.Config.VoucherCacheDir != "" {
		voucherPath := filepath.Join(r.Config.VoucherCacheDir, string(req.SerialNumber)+".json")
		voucherData, err := voucher.EncodeVoucher(v)
		if err != nil {
			r.Logger.Errorw("Failed to encode voucher for caching", "error", err, "serial_number", string(req.SerialNumber))
		} else {
			err = os.WriteFile(voucherPath, voucherData, 0600)
			if err != nil {
				r.Logger.Errorw("Failed to write voucher to cache", "error", err, "path", voucherPath)
			}
		}
	}

	return v, nil
}

// ProcessVoucherStatus processes a voucher status update from a pledge
func (r *Registrar) ProcessVoucherStatus(serialNumber voucher.SerialNumber, status *voucher.VoucherStatus) error {
	// Log the voucher status update
	r.Logger.Infof("Processing voucher status update for serial number: %s, status: %s, reason: %s",
		string(serialNumber), status.Status, status.Reason)

	// In a real implementation, we would record this status in a database
	// and potentially take action based on the status

	return nil
}

// GetAuditLog retrieves the audit log for a device from the MASA
func (r *Registrar) GetAuditLog(serialNumber voucher.SerialNumber) ([]*voucher.AuditLogEntry, error) {
	// Determine the MASA client to use
	// In a real implementation, this would use information from the pledge's IDevID to determine the manufacturer
	// For now, we'll use the MASA client for the domain name
	masaClient := r.MASAClients[r.Config.DomainName]

	if masaClient == nil {
		return nil, &types.Error{
			Code:    types.ErrMASAUnavailable,
			Message: "No MASA client available",
		}
	}

	// Request the audit log from the MASA
	entries, err := masaClient.RequestAuditLog(serialNumber)
	if err != nil {
		return nil, &types.Error{
			Code:    types.ErrMASAUnavailable,
			Message: "Failed to request audit log from MASA",
			Err:     err,
		}
	}

	return entries, nil
}

// GetVoucher retrieves a cached voucher for a device
func (r *Registrar) GetVoucher(serialNumber voucher.SerialNumber) (*voucher.Voucher, error) {
	r.voucherCacheMutex.RLock()
	v, ok := r.VoucherCache[serialNumber]
	r.voucherCacheMutex.RUnlock()

	if !ok {
		// If a voucher cache directory is configured, try to load the voucher from disk
		if r.Config.VoucherCacheDir != "" {
			voucherPath := filepath.Join(r.Config.VoucherCacheDir, string(serialNumber)+".json")
			voucherData, err := os.ReadFile(voucherPath)
			if err == nil {
				v, err = voucher.DecodeVoucher(voucherData)
				if err == nil {
					// Cache the voucher in memory
					r.voucherCacheMutex.Lock()
					r.VoucherCache[serialNumber] = v
					r.voucherCacheMutex.Unlock()
					return v, nil
				}
			}
		}

		return nil, &types.Error{
			Code:    types.ErrNotFound,
			Message: "Voucher not found",
		}
	}

	return v, nil
}
