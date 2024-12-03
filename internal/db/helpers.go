package db

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/est/internal/alogger"
	"gorm.io/gorm"
)

var logger = alogger.New(os.Stderr)

func (db *DB) SaveHTTPRequest(r *http.Request) error {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Failed to read request body: %v", err)
		return err
	}
	body := string(bodyBytes)

	r.Body.Close()

	headers := ""
	for name, values := range r.Header {
		for _, value := range values {
			headers += name + ": " + value + "\n"
		}
	}

	requestRecord := HTTPRequest{
		Method:   r.Method,
		URL:      r.URL.String(),
		Headers:  headers,
		Body:     body,
		RemoteIP: r.RemoteAddr,
	}

	err = db.Create(&requestRecord)
	if err != nil {
		logger.Errorf("Failed to save HTTP request to database: %v", err)
		return err
	}

	return nil
}

type CertificateWithStatus struct {
	Certificate x509.Certificate
	Status      CertificateStatus
}

// Save Certificate saves a certificate to the database
func (db *DB) saveCertificate(tx *gorm.DB, c *CertificateWithStatus) error {
	var algo string
	cert := c.Certificate
	// Check if empty certificate fields are present
	if cert.SerialNumber == nil || cert.Subject.CommonName == "" ||
		len(cert.Subject.Organization) == 0 || cert.NotBefore.IsZero() ||
		cert.NotAfter.IsZero() || cert.RawSubjectPublicKeyInfo == nil ||
		cert.SignatureAlgorithm == 0 {
		// logger.Errorf("Empty fields in certificate, prefilling with default values")
		// prefill the missing fields
		if cert.SerialNumber == nil {
			return fmt.Errorf("serial number is nil")
		}
		if cert.Subject.CommonName == "" {
			cert.Subject.CommonName = "Unknown"
		}
		if len(cert.Subject.Organization) == 0 {
			cert.Subject.Organization = []string{"Unknown"}
		}
		if cert.NotBefore.IsZero() {
			cert.NotBefore = time.Now()
		}
		if cert.NotAfter.IsZero() {
			cert.NotAfter = time.Now().AddDate(1, 0, 0)
		}
		if cert.RawSubjectPublicKeyInfo == nil {
			cert.RawSubjectPublicKeyInfo = []byte("Unknown")
		}
		if cert.SignatureAlgorithm == 0 {
			algo = x509.UnknownSignatureAlgorithm.String()
		}
	}

	for _, ext := range cert.Extensions {
		if !ext.Critical && ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 72}) {
			logger.Debugf("Extension OID: %v", ext.Id)
			algo = "ECDSA-SHA256 ML-DSA44 (Hybrid PQC)"
		} else {
			algo = cert.SignatureAlgorithm.String()
		}
	}

	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		algo = "ML-DSA44 (PQC)"
	}

	certificate := Certificate{
		SerialNumber:  strings.ToUpper(cert.SerialNumber.Text(16)),
		CommonName:    cert.Subject.CommonName,
		Organization:  cert.Subject.Organization[0],
		IssuedAt:      cert.NotBefore,
		ExpiresAt:     cert.NotAfter,
		SignatureAlgo: algo,
		Status:        c.Status,
	}

	// Use the transaction (tx) to create the record instead of db.Create
	err := tx.Create(&certificate).Error
	if err != nil {
		logger.Errorf("Failed to save certificate to database: %v", err)
		tx.Rollback()
		return err
	}

	return nil
}

func (db *DB) SaveCertificateFromSubject(subject string, cert x509.Certificate) error {
	// Start a new transaction
	return db.conn.Transaction(func(tx *gorm.DB) error {
		// Check if the subject exists
		var subjectRecord Subject
		result := tx.Where("common_name = ?", subject).First(&subjectRecord)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				logger.Errorf("Failed to query subject: %v", result.Error)
				return result.Error
			}

			// Create a new subject if not found
			subjectRecord = Subject{
				CommonName: subject,
			}
			err := tx.Create(&subjectRecord).Error
			if err != nil {
				logger.Errorf("Failed to create subject: %v", err)
				return err
			}
			logger.Infof("Subject %s not found, creating a new one", subject)
		}

		// Prepare a CertificateWithStatus struct for the certificate
		certificateWithStatus := &CertificateWithStatus{
			Certificate: cert,
			Status:      CertificateStatusActive,
		}

		// Call SaveCertificate to save the certificate (this will save the certificate in the database)
		err := db.saveCertificate(tx, certificateWithStatus)
		if err != nil {
			logger.Errorf("Failed to save certificate: %v", err)
			return err
		}

		// Retrieve the saved certificate based on serial number or other unique fields
		var savedCertificate Certificate
		err = tx.Where("serial_number = ?", strings.ToUpper(cert.SerialNumber.Text(16))).First(&savedCertificate).Error
		if err != nil {
			logger.Errorf("Failed to retrieve saved certificate: %v", err)
			return err
		}

		// Link the retrieved certificate to the subject
		err = tx.Model(&subjectRecord).Association("Certificates").Append(&savedCertificate)
		if err != nil {
			logger.Errorf("Failed to link certificate to subject: %v", err)
			return err
		}

		return nil
	})
}

// SaveCSR saves a certificate signing request to the database
func (db *DB) SaveCSR(csr *x509.CertificateRequest) error {
	certificateRequest := CSR{
		RequestData:  string(csr.Raw),
		CommonName:   csr.Subject.CommonName,
		Organization: csr.Subject.Organization[0],
		Email:        csr.EmailAddresses[0],
		KeyAlgorithm: csr.PublicKeyAlgorithm.String(),
		Status:       "pending",
	}

	err := db.Create(&certificateRequest)
	if err != nil {
		logger.Errorf("Failed to save CSR to database: %v", err)
		return err
	}

	return nil
}

// SaveRevocation saves a certificate revocation to the database
func (db *DB) SaveRevocation(certID uint, reason string) error {
	revocation := Revocation{
		CertificateID: certID,
		Reason:        reason,
		RevokedAt:     time.Now(),
	}

	err := db.Create(&revocation)
	if err != nil {
		logger.Errorf("Failed to save revocation to database: %v", err)
		return err
	}

	return nil
}

// UpdateCertificate updates any field of a certificate in the database
func (db *DB) UpdateCertificate(serialNumber string, updates map[string]interface{}) error {
	var certificate Certificate
	result := db.conn.Where("serial_number = ?", serialNumber).First(&certificate)
	if result.Error != nil {
		logger.Errorf("Failed to find certificate for update: %v", result.Error)
		return result.Error
	}

	result = db.conn.Model(&certificate).Updates(updates)
	if result.Error != nil {
		logger.Errorf("Failed to update certificate: %v", result.Error)
		return result.Error
	}

	return nil
}

func (db *DB) UpdateSubject(commonName string, updates map[string]interface{}) error {
	var subject Subject
	result := db.conn.Where("common_name = ?", commonName).First(&subject)
	if result.Error != nil {
		logger.Errorf("Failed to find subject for update: %v", result.Error)
		return result.Error
	}

	result = db.conn.Model(&subject).Updates(updates)
	if result.Error != nil {
		logger.Errorf("Failed to update subject: %v", result.Error)
		return result.Error
	}

	return nil
}

// GetSubject checks if a subject is present in the database
func (db *DB) GetSubject(commonName string) (subject Subject, found bool) {
	result := db.conn.Where("common_name = ?", commonName).First(&subject)
	if result.Error != nil {
		logger.Infof("No subject found: %v", result.Error)
		return subject, false
	}

	return subject, true
}

// GetCertificate checks if a certificate is present in the database
func (db *DB) GetCertificate(serialNumber string) (certificate Certificate, found bool) {
	result := db.conn.Where("serial_number = ?", serialNumber).First(&certificate)
	if result.Error != nil {
		logger.Errorf("Failed to find certificate: %v", result.Error)
		return certificate, false
	}

	return certificate, true
}

// GetRevocation checks if a certificate is revoked in the database
// returns the revocation record if found
func (db *DB) GetRevocations() ([]Certificate, bool) {
	var revocation []Certificate
	// get all revoked certificates
	result := db.conn.Where("status = ?", "revoked").Find(&revocation)

	if result.Error != nil {
		logger.Errorf("Failed to find revoked certificates: %v", result.Error)
		return revocation, false
	}

	logger.Debugf("Found %d revoked certificates", len(revocation))

	return revocation, true
}

// DisablePreviousCerts disables all previous certificates for a subject
func (db *DB) DisablePreviousCerts(commonName string, serialNumber string) error {
	var lastCert Certificate

	// Transaction to disable all previous certificates
	return db.conn.Transaction(func(tx *gorm.DB) error {
		err := tx.Where("common_name = ? AND status = ?", commonName, CertificateStatusActive).
			Order("issued_at desc").First(&lastCert).Error
		if err != nil {
			logger.Errorf("Failed to find last certificate: %v", err)
			return err
		}

		logger.Debugf("Last certificate: %s", lastCert.SerialNumber)

		// Disable all older certificates (except the latest one)
		err = tx.Model(&Certificate{}).
			Where("common_name = ? AND id != ? AND status = ?", commonName, lastCert.ID, CertificateStatusActive).
			Updates(map[string]interface{}{
				"status":         CertificateStatusRevoked,
				"revoked_at":     time.Now(),
				"revoked_reason": "superseded by new certificate with serial number " + serialNumber,
			}).Error
		if err != nil {
			logger.Errorf("Failed to disable previous certificates: %v", err)
			return err
		}

		// log all revoked certificates
		var revokedCerts []Certificate
		err = tx.Where("common_name = ? AND status = ?", commonName, CertificateStatusRevoked).Find(&revokedCerts).Error
		if err != nil {
			logger.Errorf("Failed to find revoked certificates: %v", err)
			return err
		}

		// comma separated list of revoked certificates
		var revokedSerials string
		for _, cert := range revokedCerts {
			revokedSerials += cert.SerialNumber + ", "
		}
		logger.Infof("Revoked certificates: %s", revokedSerials)

		return nil
	})
}

// GetCertificates returns all certificates from the database
func (db *DB) GetCertificates() []Certificate {
	var certificates []Certificate
	result := db.conn.Find(&certificates)
	if result.Error != nil {
		logger.Errorf("Failed to find certificates: %v", result.Error)
		return nil
	}

	if len(certificates) == 0 {
		logger.Infof("No certificates found")
	}

	return certificates
}

// GetSubjects returns all subjects from the database
func (db *DB) GetSubjects() []Subject {
	var subjects []Subject
	result := db.conn.Find(&subjects)
	if result.Error != nil {
		logger.Errorf("Failed to find subjects: %v", result.Error)
		return nil
	}

	if len(subjects) == 0 {
		logger.Infof("No subjects found")
	}

	return subjects
}

type Node struct {
	ID         int
	Name       string
	ConfigName string
	Status     NodeState
	Location   string
}

func (db *DB) GetNodes() ([]Node, error) {
	var selectedConfigurations []SelectedConfiguration
	var nodes []Node

	// Preload the necessary related data (Node and Config) to avoid N+1 queries
	err := db.conn.Preload("Node").Preload("Config").Find(&selectedConfigurations).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch selected configurations: %w", err)
	}

	// Iterate through the selected configurations to construct the Node slice
	for _, sc := range selectedConfigurations {
		if sc.Node.SerialNumber == "feldgeraet1" {
			sc.Node.SerialNumber = "Feldgerät 1"
		} else if sc.Node.SerialNumber == "feldgeraet2" {
			sc.Node.SerialNumber = "Feldgerät 2"
		} else if sc.Node.SerialNumber == "leitstelle" {
			sc.Node.SerialNumber = "Leitstelle"
		}

		nodes = append(nodes, Node{
			ID:         int(sc.Node.ID),
			Name:       sc.Node.SerialNumber,
			ConfigName: sc.Config.ConfigName,
			Status:     sc.NodeState,
			Location:   sc.Node.Locality,
		})
	}

	return nodes, nil
}

// Update Status
func (db *DB) UpdateNodeStatus(nodeID int, status NodeState) error {
	var selectedConfiguration SelectedConfiguration
	result := db.conn.Where("node_id = ?", nodeID).First(&selectedConfiguration)
	if result.Error != nil {
		logger.Errorf("Failed to find selected configuration for update: %v", result.Error)
		return result.Error
	}

	result = db.conn.Model(&selectedConfiguration).Update("node_state", status)
	if result.Error != nil {
		logger.Errorf("Failed to update selected configuration: %v", result.Error)
		return result.Error
	}

	return nil
}
