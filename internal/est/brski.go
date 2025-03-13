package est

import (
	"context"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Log field constants
const (
	logFieldModule = "Module"
)

// brskiRegistrarFromContext returns a BRSKIRegistrar implementation from the request context.
// If the CA does not implement BRSKIRegistrar, it returns nil.
func brskiRegistrarFromContext(ctx context.Context) BRSKIRegistrar {
	ca, _ := ctx.Value(ctxKeyCA).(CA)
	if ca == nil {
		return nil
	}

	brski, ok := ca.(BRSKIRegistrar)
	if !ok {
		return nil
	}

	return brski
}

// requestVoucher handles the /.well-known/brski/requestvoucher endpoint.
func requestVoucher(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	// Get the BRSKI registrar from context
	brski := brskiRegistrarFromContext(ctx)
	if brski == nil {
		logger.Infow("BRSKI registrar function not implemented by CA", logFieldModule, "brski")
		http.Error(w, "BRSKI not supported", http.StatusNotImplemented)
		return
	}

	// Get additional path segment
	aps := chi.URLParam(r, apsParamName)

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorw("Failed to read voucher request", logFieldModule, "brski", logFieldError, err.Error())
		errBodyParse.Write(w)
		return
	}
	defer consumeAndClose(r.Body)

	// Process the voucher request
	voucher, err := brski.ProcessVoucherRequest(ctx, body, aps, r)
	if err != nil {
		logger.Errorw("Failed to process voucher request", logFieldModule, "brski", logFieldError, err.Error())
		writeOnError(ctx, w, "failed to process voucher request", err)
		return
	}

	// Set the response headers
	w.Header().Set(contentTypeHeader, mimeTypePKCS7CertsOnly)
	w.Header().Set(contentTypeOptionsHeader, "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(voucher)
}

// voucherStatus handles the /.well-known/brski/voucher_status endpoint.
func voucherStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	// Get the BRSKI registrar from context
	brski := brskiRegistrarFromContext(ctx)
	if brski == nil {
		logger.Infow("BRSKI registrar function not implemented by CA", logFieldModule, "brski")
		http.Error(w, "BRSKI not supported", http.StatusNotImplemented)
		return
	}

	// Get additional path segment
	aps := chi.URLParam(r, apsParamName)

	// Get the serial number from the request
	serialNumber := r.URL.Query().Get("serial-number")
	if serialNumber == "" {
		logger.Errorw("Missing serial number", logFieldModule, "brski")
		errInvalidRequest("Missing serial number").Write(w)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorw("Failed to read voucher status", logFieldModule, "brski", logFieldError, err.Error())
		errBodyParse.Write(w)
		return
	}
	defer consumeAndClose(r.Body)

	// Process the voucher status
	err = brski.ProcessVoucherStatus(ctx, serialNumber, body, aps, r)
	if err != nil {
		logger.Errorw("Failed to process voucher status", logFieldModule, "brski", logFieldError, err.Error())
		writeOnError(ctx, w, "failed to process voucher status", err)
		return
	}

	// Set the response headers
	w.WriteHeader(http.StatusOK)
}

// registrarVoucher handles the /.well-known/brski/registrar/voucher endpoint.
func registrarVoucher(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	// Get the BRSKI registrar from context
	brski := brskiRegistrarFromContext(ctx)
	if brski == nil {
		logger.Infow("BRSKI registrar function not implemented by CA", logFieldModule, "brski")
		http.Error(w, "BRSKI not supported", http.StatusNotImplemented)
		return
	}

	// Get additional path segment
	aps := chi.URLParam(r, apsParamName)

	// Get the serial number from the request
	serialNumber := r.URL.Query().Get("serial-number")
	if serialNumber == "" {
		logger.Errorw("Missing serial number", logFieldModule, "brski")
		errInvalidRequest("Missing serial number").Write(w)
		return
	}

	// Get the voucher
	voucher, err := brski.GetVoucher(ctx, serialNumber, aps, r)
	if err != nil {
		logger.Errorw("Failed to get voucher", logFieldModule, "brski", logFieldError, err.Error())
		writeOnError(ctx, w, "failed to get voucher", err)
		return
	}

	// Set the response headers
	w.Header().Set(contentTypeHeader, mimeTypePKCS7CertsOnly)
	w.Header().Set(contentTypeOptionsHeader, "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(voucher)
}

// registrarVoucherStatus handles the /.well-known/brski/registrar/voucher_status endpoint.
func registrarVoucherStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	// Get the BRSKI registrar from context
	brski := brskiRegistrarFromContext(ctx)
	if brski == nil {
		logger.Infow("BRSKI registrar function not implemented by CA", logFieldModule, "brski")
		http.Error(w, "BRSKI not supported", http.StatusNotImplemented)
		return
	}

	// Get additional path segment
	aps := chi.URLParam(r, apsParamName)

	// Get the serial number from the request
	serialNumber := r.URL.Query().Get("serial-number")
	if serialNumber == "" {
		logger.Errorw("Missing serial number", logFieldModule, "brski")
		errInvalidRequest("Missing serial number").Write(w)
		return
	}

	// Get the voucher status
	status, err := brski.GetVoucherStatus(ctx, serialNumber, aps, r)
	if err != nil {
		logger.Errorw("Failed to get voucher status", logFieldModule, "brski", logFieldError, err.Error())
		writeOnError(ctx, w, "failed to get voucher status", err)
		return
	}

	// Set the response headers
	w.Header().Set(contentTypeHeader, mimeTypeJSON)
	w.Header().Set(contentTypeOptionsHeader, "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(status)
}

// requestAuditLog handles the /.well-known/est/requestauditlog endpoint.
func requestAuditLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	// Get the BRSKI registrar from context
	brski := brskiRegistrarFromContext(ctx)
	if brski == nil {
		logger.Infow("BRSKI registrar function not implemented by CA", logFieldModule, "brski")
		http.Error(w, "BRSKI not supported", http.StatusNotImplemented)
		return
	}

	// Get additional path segment
	aps := chi.URLParam(r, apsParamName)

	// Get the serial number from the request
	serialNumber := r.URL.Query().Get("serial-number")
	if serialNumber == "" {
		logger.Errorw("Missing serial number", logFieldModule, "brski")
		errInvalidRequest("Missing serial number").Write(w)
		return
	}

	// Get the audit log
	auditLog, err := brski.GetAuditLog(ctx, serialNumber, aps, r)
	if err != nil {
		logger.Errorw("Failed to get audit log", logFieldModule, "brski", logFieldError, err.Error())
		writeOnError(ctx, w, "failed to get audit log", err)
		return
	}

	// Set the response headers
	w.Header().Set(contentTypeHeader, mimeTypeJSON)
	w.Header().Set(contentTypeOptionsHeader, "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(auditLog)
}

// errInvalidRequest creates a new error for an invalid request with a custom message.
func errInvalidRequest(message string) *estError {
	return &estError{
		status: http.StatusBadRequest,
		desc:   message,
	}
}
