package main

import (
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
		LoggingEnabled:       cfg.ASLConfig.LoggingEnabled,
		LogLevel:             int32(cfg.ASLConfig.LogLevel),
	}

	err = asl.ASLinit(libConfig)
	if err != nil {
		log.Fatalf("Error initializing wolfSSL: %v", err)
	}

	endpointConfig := &asl.EndpointConfig{
		MutualAuthentication:    cfg.Endpoint.MutualAuthentication,
		NoEncryption:            cfg.Endpoint.NoEncryption,
    ASLKeyExchangeMethod:    asl.ASLKeyExchangeMethod(cfg.Endpoint.ASLKeyExchangeMethod),
		HybridSignatureMode:     asl.HybridSignatureMode(cfg.Endpoint.HybridSignatureMode),
		DeviceCertificateChain:  asl.DeviceCertificateChain{Path: cfg.TLS.Certs},
		PrivateKey: asl.PrivateKey{
			Path: cfg.TLS.Key,
			// TODO: only if the keys are in separate files
			AdditionalKeyBuffer: nil,
		},
		RootCertificate: asl.RootCertificate{Path: cfg.RealCA.Certs},
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

	var aslServer = httpserver.ASLHTTPServer{
		ASLEndpoint: endpoint,
		Listener:    tcpListener,
		Handler:     r,
		Logger:      logger,
	}
	go aslServer.ServeTLS()

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	/* Cleanup the wolfSSL environment */
	asl.ASLFreeEndpoint(endpoint)
}
