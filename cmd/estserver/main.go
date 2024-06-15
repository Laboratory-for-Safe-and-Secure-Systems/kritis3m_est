package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
	"github.com/ayham/est"
	"github.com/ayham/est/internal/basiclogger"
	httpserver "github.com/ayham/est/internal/httpServer"
	"github.com/ayham/est/internal/realca"
	"github.com/globalsign/pemfile"
)

const (
	defaultListenAddr   = ":8443"
	healthCheckUsername = "healthcheck"
	healthCheckEndpoint = "/healthcheck"
)

func main() {
	log.SetPrefix(fmt.Sprintf("%s: ", appName))
	log.SetFlags(0)

	flag.Usage = usage
	flag.Parse()

	// Process special-purpose flags.
	switch {
	case *fHelp:
		usage()
		return

	case *fSampleConfig:
		sampleConfig()
		return

	case *fVersion:
		version()
		return
	}

	// Load and process configuration.
	var cfg *config
	var err error
	if *fConfig != "" {
		cfg, err = configFromFile(*fConfig)
		if err != nil {
			log.Fatalf("failed to read configuration file: %v", err)
		}
	} else {
		cfg = &config{}
	}

	// Create and configure the library configuration
	libConfig := &asl.ASLConfig{
		LoggingEnabled:       true,
		LogLevel:             4,
		SecureElementSupport: false,
	}

	err = asl.ASLinit(libConfig)
	if err != nil {
		log.Fatalf("Error initializing wolfSSL: %v", err)
	}

	endpointConfig := &asl.EndpointConfig{
		MutualAuthentication:    cfg.Endpoint.MutualAuthentication,
		NoEncryption:            cfg.Endpoint.NoEncryption,
		UseSecureElement:        cfg.Endpoint.UseSecureElement,
		SecureElementImportKeys: cfg.Endpoint.SecureElementImportKeys,
		HybridSignatureMode:     asl.HybridSignatureMode(cfg.Endpoint.HybridSignatureMode),
		DeviceCertificateChain:  asl.DeviceCertificateChain{Path: cfg.TLS.Certs},
		PrivateKey: asl.PrivateKey{
			Path: cfg.TLS.Key,
			// only if the keys are in separate files
			AdditionalKeyBuffer: nil,
		},
		RootCertificate: asl.RootCertificate{Path: cfg.TLS.ClientCAs[0]},
		KeylogFile:      cfg.Endpoint.KeylogFile,
	}

	endpoint := asl.ASLsetupServerEndpoint(endpointConfig)
	// check if the endpoint is not null pointer
	if endpoint == nil {
		log.Fatalf("failed to setup server endpoint")
	}

	// Create CA.
	var ca *realca.RealCA
	if cfg.RealCA != nil {
		ca, err = realca.Load(cfg.RealCA.Certs, cfg.RealCA.Key)
		if err != nil {
			log.Fatalf("failed to create CA: %v", err)
		}
	} else {
		log.Fatalf("No CA defined in configuration file")
	}

	// Create logger. If no log file was specified, log to standard error.
	var logger est.Logger
	if cfg.Logfile == "" {
		logger = basiclogger.New(os.Stderr)
	} else {
		f, err := os.OpenFile(cfg.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		logger = basiclogger.New(f)
		defer f.Close()
	}

	// Create server TLS configuration. If a server TLS configuration was
	// specified in the configuration file, use it.
	var listenAddr = defaultListenAddr
	var serverKey interface{}
	var serverCerts []*x509.Certificate
	var clientCACerts []*x509.Certificate

	if cfg.TLS != nil {
		serverKey, err = pemfile.ReadPrivateKey(cfg.TLS.Key)
		if err != nil {
			log.Fatalf("failed to read server private key from file: %v", err)
		}

		serverCerts, err = pemfile.ReadCerts(cfg.TLS.Certs)
		if err != nil {
			log.Fatalf("failed to read server certificates from file: %v", err)
		}

		for _, certPath := range cfg.TLS.ClientCAs {
			certs, err := pemfile.ReadCerts(certPath)
			if err != nil {
				log.Fatalf("failed to read client CA certificates from file: %v", err)
			}
			clientCACerts = append(clientCACerts, certs...)
		}

		listenAddr = cfg.TLS.ListenAddr
	} else {
		log.Fatalf("No TLS configuration defined in configuration file")
	}

	if serverKey == nil {
		log.Fatalf("No server key defined in configuration file")
	}

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	// Create server mux.
	r, err := est.NewRouter(&est.ServerConfig{
		CA:           ca,
		Logger:       logger,
		AllowedHosts: cfg.AllowedHosts,
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		RateLimit:    cfg.RateLimit,
	})
	if err != nil {
		log.Fatalf("failed to create new EST router: %v", err)
	}

	// Create a custom TCP listener
	tcpListener, err := net.Listen("tcp", listenAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	logger.Infof("Starting EST server")

	go httpserver.ServeCustomTLS(endpoint, tcpListener, r)

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	/* Cleanup the wolfSSL environment */
	asl.ASLFreeEndpoint(endpoint)
}
