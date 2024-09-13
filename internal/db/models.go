package db

import (
	"gorm.io/gorm"
	"time"
)

type Certificate struct {
	gorm.Model
	SerialNumber  string    `gorm:"unique;not null"`
	CommonName    string    `gorm:"not null"`
	Organizations []string  `gorm:"not null;type:text"`
	Emails        []string  `gorm:"not null;type:text"`
	IssuedAt      time.Time `gorm:"not null"`
	ExpiresAt     time.Time `gorm:"not null"`
	PublicKey     string    `gorm:"not null;type:text"`
	PrivateKey    string    `gorm:"not null;type:text"`
	SignatureAlgo string    `gorm:"not null"`
	Status        string    `gorm:"not null"`
	RevokedAt     time.Time
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
}

type HTTPRequest struct {
	gorm.Model
	Method   string `gorm:"not null"`
	URL      string `gorm:"not null"`
	Headers  string `gorm:"type:text"`
	Body     string `gorm:"type:text"`
	RemoteIP string `gorm:"not null"`
}
