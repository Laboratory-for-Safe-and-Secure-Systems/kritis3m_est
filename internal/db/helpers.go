package db

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
)

func (db *DB) SaveHTTPRequest(r *http.Request) error {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read request body:", err)
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
		log.Println("Failed to save request to database:", err)
		return err
	}

	log.Printf("Saved request: %+v\n", requestRecord)
	return nil
}

// Save Certificate saves a certificate to the database
func (db *DB) SaveCertificate(cert *x509.Certificate) error {
	certificate := Certificate{
		SerialNumber:  cert.SerialNumber.String(),
		CommonName:    cert.Subject.CommonName,
		Organizations: cert.Subject.Organization,
		Emails:        cert.EmailAddresses,
		IssuedAt:      cert.NotBefore,
		ExpiresAt:     cert.NotAfter,
		PublicKey:     string(cert.RawSubjectPublicKeyInfo),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		Status:        "valid",
	}

	err := db.Create(&certificate)
	if err != nil {
		log.Println("Failed to save certificate to database:", err)
		return err
	}

	log.Printf("Saved certificate: %+v\n", certificate)
	return nil
}
