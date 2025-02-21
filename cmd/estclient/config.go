package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/kritis3m_pki"
	"github.com/ThalesIgnite/crypto11"
	"golang.org/x/term"

	"github.com/globalsign/pemfile"
)

// config contains configuration options.
type config struct {
	Server            string            `json:"server"`
	APS               string            `json:"additional_path_segment"`
	AdditionalHeaders map[string]string `json:"additional_headers,omitempty"`
	HostHeader        string            `json:"host_header"`
	Username          string            `json:"username"`
	Password          string            `json:"password"`
	Explicit          string            `json:"explicit_anchor"`
	Implicit          string            `json:"implicit_anchor"`
	PrivateKey        *privateKey       `json:"private_key,omitempty"`
	Certificate       string            `json:"client_certificates"`
	LibPath           string            `json:"lib_path,omitempty"`
	certificates      []*x509.Certificate
	ekcerts           []*x509.Certificate
	baseDir           string
	closeFuncs        []func() error
	explicitAnchor    *x509.CertPool
	flagSet           *flag.FlagSet
	flags             map[string]string
	implicitAnchor    *x509.CertPool
	insecure          bool
	openPrivateKey    interface{}
	separator         string
	timeout           time.Duration
}

// privateKey specifies the source of a private key, which could be a file,
// a hardware security module (HSM), a Trusted Platform Module (TPM) device,
// or another source.
type privateKey struct {
	Path   string
	PKCS11 *kritis3m_pki.PKCS11Module
	HSM    *hsmKey
}

// hsmKey is an HSM-resident private key.
type hsmKey struct {
	LibraryPath string   `json:"pkcs11_library_path"`
	Label       string   `json:"token_label"`
	PIN         string   `json:"token_pin"`
	KeyID       *big.Int `json:"key_id"`
}

const (
	configDirectoryVar = "ESTCLIENT_CONFIG_DIRECTORY"
	hsmKeyLabel        = "hsm"
)

var (
	errNoPrivateKey = errors.New("no private key provided")
	errNoServer     = errors.New("EST server not specified")
)

// Close releases resources associated with a configuration.
func (cfg *config) Close() (err error) {
	for _, closeFunc := range cfg.closeFuncs {
		err = closeFunc()
	}

	return
}

// FlagWasPassed reports whether a flag was passed at the command line.
func (cfg *config) FlagWasPassed(name string) bool {
	_, ok := cfg.flags[name]
	return ok
}

// FlagValue returns the raw (string) value of a flag, or the empty string if
// it was not set.
func (cfg *config) FlagValue(name string) string {
	v, _ := cfg.flags[name]
	return v
}

// MakeContext returns a context with the configured timeout, and its cancel
// function.
func (cfg *config) MakeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cfg.timeout)
}

// makeClient builds an EST client from a configuration file, overriding the
// values with command line options, if applicable.
func (cfg *config) MakeClient() (*est.Client, error) {
	client := est.Client{
		Host:                  cfg.Server,
		AdditionalPathSegment: cfg.APS,
		AdditionalHeaders:     cfg.AdditionalHeaders,
		ExplicitAnchor:        cfg.Explicit,
		ImplicitAnchor:        cfg.Implicit,
		HostHeader:            cfg.HostHeader,
		PrivateKeyPath:        cfg.PrivateKey.Path,
		LibPath:               cfg.LibPath,
		CertificatePath:       cfg.Certificate,
		Username:              cfg.Username,
		Password:              cfg.Password,
		InsecureSkipVerify:    cfg.insecure,
	}

	// Host is the only required field for all operations.
	if client.Host == "" {
		return nil, errNoServer
	}

	return &client, nil
}

// GenerateCSR generates a certificate signing request. If the argument is
// nil, the private key from the configuration will be used.
func (cfg *config) GenerateCSR(key interface{}, tmpl *x509.CertificateRequest) (*x509.CertificateRequest, error) {
	if key == nil {
		if cfg.openPrivateKey == nil {
			return nil, errNoPrivateKey
		}
		key = cfg.openPrivateKey
	}

	var err error
	if tmpl == nil {
		tmpl, err = cfg.CSRTemplate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate certificate request template: %v", err)
		}
	}

	err = kritis3m_pki.Kritis3mPKI.CreateCSR(kritis3m_pki.SigningRequestMetadata{
		CSR: tmpl,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	csr, err := kritis3m_pki.Kritis3mPKI.FinalizeCSR()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize certificate request: %v", err)
	}

	return csr, nil
}

// CSRTemplate generates a certificate request template from flags.
func (cfg *config) CSRTemplate() (*x509.CertificateRequest, error) {
	tmpl := &x509.CertificateRequest{}

	// Process single string flags.
	for _, f := range []struct {
		name  string
		value *string
	}{
		{commonNameFlag, &tmpl.Subject.CommonName},
		{serialNumberFlag, &tmpl.Subject.SerialNumber},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = v
		}
	}

	// Process flags which accept a single string, but which are stored in
	// a string slice.
	for _, f := range []struct {
		name  string
		value *[]string
	}{
		{organizationFlag, &tmpl.Subject.Organization},
		{streetAddressFlag, &tmpl.Subject.StreetAddress},
		{localityFlag, &tmpl.Subject.Locality},
		{provinceFlag, &tmpl.Subject.Province},
		{postalCodeFlag, &tmpl.Subject.PostalCode},
		{countryFlag, &tmpl.Subject.Country},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = []string{v}
		}
	}

	// Process flags which are lists of strings.
	for _, f := range []struct {
		name  string
		value *[]string
	}{
		{organizationalUnitFlag, &tmpl.Subject.OrganizationalUnit},
		{dnsNamesFlag, &tmpl.DNSNames},
		{emailsFlag, &tmpl.EmailAddresses},
	} {
		if v, ok := cfg.flags[f.name]; ok {
			*f.value = strings.Split(v, cfg.separator)
		}
	}

	// Process SAN IP addresses.
	if v, ok := cfg.flags[ipsFlag]; ok {
		for _, strIP := range strings.Split(v, cfg.separator) {
			ip := net.ParseIP(strIP)
			if ip == nil {
				return nil, fmt.Errorf("failed to parse IP address %q", strIP)
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}

	// Process SAN URIs.
	if v, ok := cfg.flags[urisFlag]; ok {
		for _, strURI := range strings.Split(v, cfg.separator) {
			uri, err := url.Parse(strURI)
			if err != nil {
				return nil, fmt.Errorf("failed to parse URI: %v", err)
			}
			tmpl.URIs = append(tmpl.URIs, uri)
		}
	}

	return tmpl, nil
}

// Get returns a private key and a close function.
func (k *privateKey) Get(baseDir string) (interface{}, func() error, error) {
	switch {
	case k.Path != "":
		keyData, key, err := kritis3m_pki.Kritis3mPKI.LoadPrivateKey(fullPath(baseDir, k.Path), k.PKCS11)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load private key: %w", err)
		}
		kritis3m_pki.Kritis3mPKI.EntityKey = key
		return keyData, func() error { return nil }, nil

	case k.HSM != nil:
		return k.HSM.Get(baseDir)
	}

	return nil, nil, errNoPrivateKey
}

// Get returns a private key and a close function.
func (k *hsmKey) Get(baseDir string) (key interface{}, closeFunc func() error, err error) {
	closeFunc = func() error { return nil }
	defer func() {
		if err != nil {
			closeFunc()
			closeFunc = nil
		}
	}()

	// Get the HSM PIN from the terminal if one was not specified in the
	// config file.
	if k.PIN == "" {
		var pin []byte
		pin, err = passwordFromTerminal("PIN", "HSM")
		if err != nil {
			err = fmt.Errorf("failed to get HSM PIN: %w", err)
			return
		}

		k.PIN = string(pin)
	}

	var p *crypto11.Context
	p, err = crypto11.Configure(&crypto11.Config{
		Path:       fullPath(baseDir, k.LibraryPath),
		TokenLabel: k.Label,
		Pin:        k.PIN,
	})
	if err != nil {
		err = fmt.Errorf("failed to configure PKCS11: %w", err)
		return
	}
	closeFunc = func() error {
		return p.Close()
	}

	key, err = p.FindKeyPair(k.KeyID.Bytes(), nil)
	if err != nil {
		err = fmt.Errorf("failed to find key pair: %w", err)
		return
	} else if key == nil {
		err = errors.New("failed to find key pair")
		return
	}

	return
}

// UnmarshalJSON parses a JSON-encoded value and stores the result in the
// object.
func (k *privateKey) UnmarshalJSON(b []byte) error {
	// If the value is a string, then it's a simple file path.
	var fp string
	if err := json.Unmarshal(b, &fp); err == nil {
		*k = privateKey{
			Path: fp,
		}
		return nil
	}

	// Otherwise, parse the object into a map and make sure we have exactly
	// one object defined.
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}

	if len(obj) == 0 {
		return errNoPrivateKey
	} else if len(obj) > 1 {
		return errors.New("more than one private key provided")
	}

	// Unmarshal object depending on type.
	if msg, ok := obj[hsmKeyLabel]; ok {
		var s hsmKey
		if err := json.Unmarshal(msg, &s); err != nil {
			return err
		}

		*k = privateKey{HSM: &s}
	} else {
		return errors.New("unknown private key format")
	}

	return nil
}

// newConfig returns a configuration object from a file.
func newConfig(set *flag.FlagSet) (config, error) {
	loglevel := int32(kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_WRN)
	var cfg = config{
		flagSet:   set,
		flags:     make(map[string]string),
		separator: sepChar,
		timeout:   defaultTimeout,
	}

	// Store values of set command line flags.
	cfg.flagSet.Visit(func(f *flag.Flag) {
		cfg.flags[f.Name] = f.Value.String()
	})

	// Override defaults from command line, if provided.
	if v, ok := cfg.flags[separatorFlag]; ok {
		cfg.separator = v
	}

	if d, ok := cfg.flags[timeoutFlag]; ok {
		var err error
		cfg.timeout, err = time.ParseDuration(d)
		if err != nil {
			return config{}, fmt.Errorf("failed to parse -%s flag: %v", timeoutFlag, err)
		}
	}

	// Note that -insecure can deliberately only be specified at the command
	// line, and not in the configuration file.
	if v, ok := cfg.flags[insecureFlag]; ok {
		var err error
		cfg.insecure, err = strconv.ParseBool(v)
		if err != nil {
			return config{}, fmt.Errorf("failed to parse -%s flag: %v", insecureFlag, err)
		}
	}

	// Get working directory.
	wd, err := os.Getwd()
	if err != nil {
		return config{}, fmt.Errorf("failed to get working directory: %v", err)
	}

	// Parse configuration file, if provided.
	if filename, ok := cfg.flags[configFlag]; ok {
		// If filename is not an absolute path, look for it in a set sequence
		// of locations.
		if !filepath.IsAbs(filename) {
			// Check current working directory first.
			searchPaths := []string{wd}

			// Check in the directory specified by the ESTCLIENT_CONFIG_DIRECTORY
			// environment variable, if set.
			if cd, ok := os.LookupEnv(configDirectoryVar); ok {
				info, err := os.Stat(cd)
				if err == nil && info.IsDir() && filepath.IsAbs(cd) {
					searchPaths = append(searchPaths, cd)
				}
			}

			// Check in the user's home directory, if we can find it.
			if hd, err := os.UserHomeDir(); err == nil {
				searchPaths = append(searchPaths, hd)
			}

			// Search for the file itself.
			for _, searchPath := range searchPaths {
				fp := filepath.Join(searchPath, filename)
				if info, err := os.Stat(fp); err == nil && info.Mode().IsRegular() {
					filename = fp
					break
				}
			}
		}

		// Read the file and parse the configuration.
		data, err := os.ReadFile(filename)
		if err != nil {
			return config{}, fmt.Errorf("failed to open configuration file: %v", err)
		}

		if err := json.Unmarshal(data, &cfg); err != nil {
			return config{}, fmt.Errorf("failed to unmarshal configuration file: %v", err)
		}

		cfg.baseDir = filepath.Clean(filepath.Dir(filename))
	}

	// Override configuration file values from command line, if specified
	if _, ok := cfg.flags[verboseFlag]; ok {
		loglevel = 3
	}

	if _, ok := cfg.flags[debugFlag]; ok {
		loglevel = 4
	}

	if aps, ok := cfg.flags[apsFlag]; ok {
		cfg.APS = aps
	}

	if server, ok := cfg.flags[serverFlag]; ok {
		cfg.Server = server
	}

	if hdr, ok := cfg.flags[hostHeaderFlag]; ok {
		cfg.HostHeader = hdr
	}

	if username, ok := cfg.flags[usernameFlag]; ok {
		cfg.Username = username
	}

	if password, ok := cfg.flags[passwordFlag]; ok {
		cfg.Password = password
	}

	if hdrs, ok := cfg.flags[headersFlag]; ok {
		cfg.AdditionalHeaders = make(map[string]string)
		for _, hdr := range strings.Split(hdrs, cfg.separator) {
			vals := strings.SplitN(hdr, ":", 2)
			name := vals[0]
			val := ""
			if len(vals) >= 2 {
				val = vals[1]
			}

			cfg.AdditionalHeaders[strings.TrimSpace(name)] = strings.TrimSpace(val)
		}
	}

	aslConfig := &asl.ASLConfig{
		LogLevel:       loglevel,
		LoggingEnabled: true,
	}
	err = asl.ASLinit(aslConfig)
	if err != nil {
		return config{}, fmt.Errorf("failed to initialize ASL: %w", err)
	}

	// Initialize PKI
	err = kritis3m_pki.InitPKI(&kritis3m_pki.KRITIS3MPKIConfiguration{
		LogLevel:       loglevel,
		LoggingEnabled: true,
	})
	if err != nil {
		return config{}, fmt.Errorf("failed to initialize PKI: %w", err)
	}

	// Process explicit and implicit anchor databases.
	for _, anchor := range []struct {
		name   string
		flag   string
		field  *string
		anchor **x509.CertPool
	}{
		{
			name:   "explicit",
			flag:   explicitAnchorFlag,
			field:  &cfg.Explicit,
			anchor: &cfg.explicitAnchor,
		},
		{
			name:   "implicit",
			flag:   implicitAnchorFlag,
			field:  &cfg.Implicit,
			anchor: &cfg.implicitAnchor,
		},
	} {
		if filename, ok := cfg.flags[anchor.flag]; ok {
			*anchor.field = fullPath(wd, filename)
		} else if *anchor.field != "" {
			*anchor.field = fullPath(cfg.baseDir, *anchor.field)
		}

		if *anchor.field != "" {
			*anchor.anchor = x509.NewCertPool()

			certs, err := pemfile.ReadCerts(*anchor.field)
			if err != nil {
				return config{}, fmt.Errorf("failed to read %s anchor file: %v", anchor.name, err)
			}

			for _, cert := range certs {
				(*anchor.anchor).AddCert(cert)
			}
		}
	}

	// Process client certificate(s).
	if filename, ok := cfg.flags[certsFlag]; ok {
		cfg.Certificate = fullPath(wd, filename)
	} else if cfg.Certificate != "" {
		cfg.Certificate = fullPath(cfg.baseDir, cfg.Certificate)
	}

	if cfg.Certificate != "" {
		certs, err := pemfile.ReadCerts(cfg.Certificate)
		if err != nil {
			return config{}, fmt.Errorf("failed to read client certificates: %v", err)
		}

		cfg.certificates = certs
	}

	// Process TPM endorsement key certificate(s).
	var ekCertsPath string
	if filename, ok := cfg.flags[ekcertsFlag]; ok {
		ekCertsPath = fullPath(wd, filename)
	}

	if ekCertsPath != "" {
		ekcerts, err := pemfile.ReadCerts(ekCertsPath)
		if err != nil {
			return config{}, fmt.Errorf("failed to read endorsement key certificates: %v", err)
		}

		cfg.ekcerts = ekcerts
	}

	if libPath, ok := cfg.flags[pkcs11libFlag]; ok {
		cfg.LibPath = fullPath(wd, libPath)
		kritis3m_pki.Kritis3mPKI.PKCS11 = kritis3m_pki.PKCS11Config{
			EntityModule: &kritis3m_pki.PKCS11Module{
				Path: cfg.LibPath,
				Pin:  "",
				Slot: -1,
			},
			IssuerModule: nil,
		}
	}

	// Process private key. Note that a private key located in a file is the
	// only type which can be specified at the command line.
	if filename, ok := cfg.flags[keyFlag]; ok {
		cfg.PrivateKey = &privateKey{Path: fullPath(wd, filename), PKCS11: kritis3m_pki.Kritis3mPKI.PKCS11.EntityModule}
	}

	if cfg.PrivateKey != nil {
		privkey, closeFunc, err := cfg.PrivateKey.Get(cfg.baseDir)
		if err != nil {
			return config{}, fmt.Errorf("failed to get private key: %v", err)
		}

		cfg.openPrivateKey = privkey
		cfg.closeFuncs = append(cfg.closeFuncs, closeFunc)
	}

	aslCloseFunc := func() error {
		asl.ASLshutdown()
		return nil
	}
	pkiCloseFunc := func() error {
		kritis3m_pki.Kritis3mPKI.Cleanup()
		return nil
	}

	cfg.closeFuncs = append(cfg.closeFuncs, aslCloseFunc)
	cfg.closeFuncs = append(cfg.closeFuncs, pkiCloseFunc)

	return cfg, nil
}

// passwordFromTerminal prompts for a password at the terminal.
func passwordFromTerminal(cred, target string) ([]byte, error) {
	// Open the (POSIX standard) /dev/tty to ensure we're reading from and
	// writing to an actual terminal. If /dev/tty doesn't exist, we're
	// probably on Windows, so just check if os.Stdin is a terminal, and
	// use it if it is.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !os.IsNotExist(err) || !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("failed to open terminal: %w", err)
		}
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	tty.Write([]byte(fmt.Sprintf("Enter %s for %s: ", cred, target)))
	pass, err := term.ReadPassword(int(tty.Fd()))
	tty.Write([]byte("\n"))

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	return pass, nil
}

// fullPath returns filename if it is an absolute path, or filename joined to
// baseDir if it is not.
func fullPath(baseDir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}

	return filepath.Clean(filepath.Join(baseDir, filename))
}
