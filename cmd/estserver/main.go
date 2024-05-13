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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ayham/est"
	"github.com/ayham/est/internal/basiclogger"
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

	// Create mock CA. If no mock CA was specified in the configuration file,
	// create a transient one.
	var ca *mockca.MockCA
	if cfg.MockCA != nil {
		ca, err = mockca.NewFromFiles(cfg.MockCA.Certs, cfg.MockCA.Key)
		if err != nil {
			log.Fatalf("failed to create mock CA: %v", err)
		}
	} else {
		ca, err = mockca.NewTransient()
		if err != nil {
			log.Fatalf("failed to create mock CA: %v", err)
		}
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

	var tlsCerts [][]byte
	for i := range serverCerts {
		tlsCerts = append(tlsCerts, serverCerts[i].Raw)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range clientCACerts {
		clientCAs.AddCert(cert)
	}

	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsCerts,
				PrivateKey:  serverKey,
				Leaf:        serverCerts[0],
			},
		},
		ClientCAs: clientCAs,
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

	// Create and start server.
	s := &http.Server{
		Addr:      listenAddr,
		Handler:   r,
		TLSConfig: tlsCfg,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	logger.Infof("Starting EST server")

	go s.ListenAndServeTLS("", "")

	// Wait for signal.
	got := <-stop

	// Shutdown server.
	logger.Infof("Closing EST server with signal %v", got)

	s.Close()
}
