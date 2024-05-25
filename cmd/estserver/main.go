/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	"github.com/ayham/est"
	"github.com/ayham/est/internal/basiclogger"
	httpserver "github.com/ayham/est/internal/httpServer"
	"github.com/ayham/est/internal/realca"
	wolfSSL "github.com/ayham291/go-wolfssl"
	"github.com/globalsign/pemfile"
)

const (
	defaultListenAddr   = ":8443"
	healthCheckUsername = "healthcheck"
	healthCheckEndpoint = "/healthcheck"
)

func main() {

	/* Initialize wolfSSL */
	method := wolfSSL.Method{Name: "TLSv1.3"}

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

	ctx := wolfSSL.InitWolfSSL(cfg.TLS.Certs, cfg.RealCA.Certs, cfg.TLS.Key, false, true, method)

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

	go httpserver.ServeCustomTLS(ctx, tcpListener, r)

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	/* Cleanup wolfSSL_CTX object */
	wolfSSL.WolfSSL_CTX_free((*wolfSSL.WOLFSSL_CTX)(ctx))
	/* Cleanup the wolfSSL environment */
	wolfSSL.WolfSSL_Cleanup()
}
