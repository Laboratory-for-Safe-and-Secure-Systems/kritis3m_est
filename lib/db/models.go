package db

import (
	"time"

	"gorm.io/gorm"
)

// List of models used in the application
var modelTypes = []interface{}{
	Subject{},
	Certificate{},
	CSR{},
	Revocation{},
	HTTPRequest{},
}

// enum for CertificateStatus
type CertificateStatus string

const (
	CertificateStatusPending CertificateStatus = "pending"
	CertificateStatusActive  CertificateStatus = "active"
	CertificateStatusRevoked CertificateStatus = "revoked"
)

type Subject struct {
	gorm.Model
	CommonName    string        `gorm:"unique;not null"`
	Reenrolled    bool          `gorm:"not null;default:false"`
	ReenrolledAt  time.Time     `gorm:"default:null"`
	ReenrollCount int           `gorm:"not null;default:0"`
	Revoked       bool          `gorm:"not null;default:false"`
	RevokedAt     time.Time     `gorm:"default:null"`
	RevokedReason string        `gorm:"default:null"`
	Certificates  []Certificate `gorm:"foreignKey:CommonName;references:CommonName"`
	CSRs          []CSR         `gorm:"foreignKey:CommonName;references:CommonName"`
}

type Certificate struct {
	gorm.Model
	SerialNumber  string            `gorm:"unique;not null"`
	CommonName    string            `gorm:"not null"`
	Organization  string            `gorm:"not null;type:text"`
	IssuedAt      time.Time         `gorm:"not null"`
	ExpiresAt     time.Time         `gorm:"not null"`
	SignatureAlgo string            `gorm:"not null"`
	Status        CertificateStatus `gorm:"not null"`
	RevokedAt     time.Time         `gorm:"default:null"`
	RevokedReason string            `gorm:"default:null"`
}

type CSR struct {
	gorm.Model
	RequestData  string `gorm:"not null;type:text"`
	CommonName   string `gorm:"not null"`
	Organization string `gorm:"not null"`
	Email        string `gorm:"not null"`
	KeyAlgorithm string `gorm:"not null"`
	Status       string `gorm:"not null"`
	ApprovedAt   time.Time
	RejectedAt   time.Time
}

type Revocation struct {
	gorm.Model
	CertificateID uint      `gorm:"not null"`
	Reason        string    `gorm:"not null"`
	RevokedAt     time.Time `gorm:"not null"`
	Certificate   Certificate
}

type HTTPRequest struct {
	gorm.Model
	Method   string `gorm:"not null"`
	URL      string `gorm:"not null"`
	Headers  string `gorm:"type:text"`
	Body     string `gorm:"type:text"`
	RemoteIP string `gorm:"not null"`
}
