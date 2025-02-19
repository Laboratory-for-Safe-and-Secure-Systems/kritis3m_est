package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/alogger"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/aslhttpserver"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/est"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/kritis3m_pki"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/realca"
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
		log.Fatalf("No configuration file specified")
	}

	// Create and configure the library configuration
	libConfig := &asl.ASLConfig{
		LoggingEnabled: cfg.ASLConfig.LoggingEnabled,
		LogLevel:       int32(cfg.ASLConfig.LogLevel),
	}

	// Load PKCS11 configuration
	pkcs11Config := kritis3m_pki.PKCS11Config{
		EntityModule: nil,
		IssuerModule: &kritis3m_pki.PKCS11Module{
			Path: cfg.RealCA.IssuerModule.Path,
			Pin:  cfg.RealCA.IssuerModule.Pin,
			Slot: cfg.RealCA.IssuerModule.Slot,
		},
	}

	err = asl.ASLinit(libConfig)
	if err != nil {
		log.Fatalf("Error initializing ASL: %v", err)
	}

	endpointConfig := &asl.EndpointConfig{
		MutualAuthentication: cfg.TLS.ASLEndpoint.MutualAuthentication,
		ASLKeyExchangeMethod: asl.ASLKeyExchangeMethod(cfg.TLS.ASLEndpoint.ASLKeyExchangeMethod),
		Ciphersuites:         cfg.TLS.ASLEndpoint.Ciphersuites,
		PreSharedKey: asl.PreSharedKey{
			Enable: false,
		},
		DeviceCertificateChain: asl.DeviceCertificateChain{Path: cfg.TLS.Certs},
		PrivateKey: asl.PrivateKey{
			Path: cfg.TLS.Key,
			// TODO: only if the keys are in separate files
			AdditionalKeyBuffer: nil,
		},
		RootCertificate: asl.RootCertificate{Path: cfg.RealCA.Certs},
		KeylogFile:      cfg.TLS.ASLEndpoint.KeylogFile,
		PKCS11: asl.PKCS11ASL{
			Path: cfg.TLS.EntityModule.Path,
			Pin:  cfg.TLS.EntityModule.Pin,
		},
	}

	endpoint := asl.ASLsetupServerEndpoint(endpointConfig)
	// check if the endpoint is not null pointer
	if endpoint == nil {
		log.Fatalf("failed to setup server endpoint")
	}

	err = kritis3m_pki.InitPKI(&kritis3m_pki.KRITIS3MPKIConfiguration{
		LogLevel:       int32(cfg.ASLConfig.LogLevel),
		LoggingEnabled: true,
	})
	if err != nil {
		log.Fatalf("failed to initialize PKI: %v", err)
	}

	// Create CA.
	var ca *realca.RealCA
	if cfg.RealCA != nil {
		ca, err = realca.Load(cfg.RealCA.Certs, cfg.RealCA.Key, pkcs11Config)
		if err != nil {
			log.Fatalf("failed to create CA: %v", err)
		}
	} else {
		log.Fatalf("No CA defined in configuration file")
	}

	// Create logger. If no log file was specified, log to standard error.
	var logger est.Logger
	if cfg.Logfile == "" {
		logger = alogger.New(os.Stderr)
	} else {
		f, err := os.OpenFile(cfg.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		logger = alogger.New(f)
		defer f.Close()
	}

	// Create server TLS configuration. If a server TLS configuration was
	// specified in the configuration file, use it.
	var listenAddr = defaultListenAddr

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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	logger.Infof("Starting EST server")

	var aslServer = aslhttpserver.ASLServer{
		Server: &http.Server{
			Addr:    listenAddr,
			Handler: r,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if aslConn, ok := c.(*aslhttpserver.ASLConn); ok {
					if aslConn.TLSState != nil {
						// Attach the TLS state to the context
						return context.WithValue(ctx, aslhttpserver.TLSStateKey, aslConn.TLSState)
					}
				}
				return ctx
			},
		},
		ASLTLSEndpoint: endpoint,
	}

	go func() {
		err := aslServer.ListenAndServeASLTLS()
		if err != nil {
			log.Fatalf("failed to start ASL server: %v", err)
		}
	}()

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	/* Cleanup the wolfSSL environment */
	asl.ASLFreeEndpoint(endpoint)
}
