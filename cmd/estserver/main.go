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
	aslListener "github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/listener"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/alogger"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/aslhttpserver"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/common"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/est"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/kritis3m_pki"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/lib/realca"
	"github.com/rs/zerolog"
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

	aslLogLevel := asl.ASL_LOG_LEVEL_WRN
	switch cfg.LogLevel {
	case 1:
		aslLogLevel = asl.ASL_LOG_LEVEL_ERR
	case 2:
		aslLogLevel = asl.ASL_LOG_LEVEL_WRN
	case 3:
		aslLogLevel = asl.ASL_LOG_LEVEL_INF
	case 4:
		aslLogLevel = asl.ASL_LOG_LEVEL_DBG
	default:
		log.Fatalf("Invalid log level: %d", cfg.LogLevel)
	}

	// Create and configure the library configuration
	libConfig := &asl.ASLConfig{
		LoggingEnabled: true,
		LogLevel:       int32(aslLogLevel),
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
		RootCertificates: asl.RootCertificates{Paths: cfg.TLS.ClientCAs},
		KeylogFile:       cfg.TLS.ASLEndpoint.KeylogFile,
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

	pkiLogLevel := kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_WRN
	switch cfg.LogLevel {
	case 1:
		pkiLogLevel = kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_ERR
	case 2:
		pkiLogLevel = kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_WRN
	case 3:
		pkiLogLevel = kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_INF
	case 4:
		pkiLogLevel = kritis3m_pki.KRITIS3M_PKI_LOG_LEVEL_DBG
	default:
		log.Fatalf("Invalid log level: %d", cfg.LogLevel)
	}

	err = kritis3m_pki.InitPKI(&kritis3m_pki.KRITIS3MPKIConfiguration{
		LogLevel:       int32(pkiLogLevel),
		LoggingEnabled: true,
	})
	if err != nil {
		log.Fatalf("failed to initialize PKI: %v", err)
	}

	estLogLevel := zerolog.WarnLevel
	switch cfg.LogLevel {
	case 1:
		estLogLevel = zerolog.ErrorLevel
	case 2:
		estLogLevel = zerolog.WarnLevel
	case 3:
		estLogLevel = zerolog.InfoLevel
	case 4:
		estLogLevel = zerolog.DebugLevel
	default:
		log.Fatalf("Invalid log level: %d", cfg.LogLevel)
	}

	// Create logger. If no log file was specified, log to standard error.
	var logger est.Logger
	if cfg.Logfile == "" {
		logger = alogger.New(os.Stderr, estLogLevel)
	} else {
		f, err := os.OpenFile(cfg.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		logger = alogger.New(f, estLogLevel)
		defer f.Close()
	}

	// Set default validity if not specified.
	if cfg.RealCA.Validity == 0 {
		logger.Infof("No validity specified in configuration file, using default value of 365 days")
		cfg.RealCA.Validity = 365
	}

	// Create CA.
	var ca *realca.RealCA
	if cfg.RealCA != nil {
		// Convert the configuration types to match the RealCA types
		backends := make([]realca.PKIBackendConfig, len(cfg.RealCA.Backends))
		for i, backend := range cfg.RealCA.Backends {
			backends[i] = realca.PKIBackendConfig{
				APS: backend.APS,
				Module: &kritis3m_pki.PKCS11Module{
					Path: backend.Module.Path,
					Pin:  backend.Module.Pin,
					Slot: backend.Module.Slot,
				},
				Certificates: backend.Certificates,
				PrivateKey:   backend.PrivateKey,
			}
		}

		var defaultBackend *realca.PKIBackendConfig
		if cfg.RealCA.DefaultBackend != nil {
			defaultBackend = &realca.PKIBackendConfig{
				Module: &kritis3m_pki.PKCS11Module{
					Path: cfg.RealCA.DefaultBackend.Module.Path,
					Pin:  cfg.RealCA.DefaultBackend.Module.Pin,
					Slot: cfg.RealCA.DefaultBackend.Module.Slot,
				},
				Certificates: cfg.RealCA.DefaultBackend.Certificates,
				PrivateKey:   cfg.RealCA.DefaultBackend.PrivateKey,
			}
		}

		ca, err = realca.New(backends, defaultBackend, logger, cfg.RealCA.Validity)
		if err != nil {
			log.Fatalf("failed to create CA: %v", err)
		}
	} else {
		log.Fatalf("No CA defined in configuration file")
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
				if aslConn, ok := c.(*aslListener.ASLConn); ok {
					if aslConn.TLSState != nil {
						// Attach the TLS state to the context
						return context.WithValue(ctx, common.TLSStateKey, aslConn.TLSState)
					}
				}
				return ctx
			},
		},
		ASLTLSEndpoint: endpoint,
		Logger:         logger,
		DebugLog:       cfg.LogLevel == 4,
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
	asl.ASLshutdown()
}
