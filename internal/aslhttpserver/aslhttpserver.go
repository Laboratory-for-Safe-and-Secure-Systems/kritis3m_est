package aslhttpserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	aslListener "github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/listener"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/logging"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_est/internal/common"
)

// ASLServer struct that embeds http.Server and uses custom ASL TLS listener
type ASLServer struct {
	*http.Server
	ASLTLSEndpoint *asl.ASLEndpoint // Custom ASL Endpoint configuration
	Logger         common.Logger
	DebugLog       bool
}

// Constructor for ASLServer
func NewASLServer(addr string, handler http.Handler, endpointConfig *asl.EndpointConfig) *ASLServer {
	// Initialize http.Server
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Set the ConnContext function
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if aslConn, ok := c.(*aslListener.ASLConn); ok {
			ctx = context.WithValue(ctx, common.TLSStateKey, aslConn.TLSState)
		}
		return ctx
	}

	// Setup ASL Endpoint (optional at initialization)
	var aslEndpoint *asl.ASLEndpoint
	if endpointConfig != nil {
		aslEndpoint = asl.ASLsetupServerEndpoint(endpointConfig)
		if aslEndpoint == nil {
			log.Fatalf("Failed to setup ASL endpoint")
		}
	}

	// Return the ASLServer instance
	return &ASLServer{
		Server:         srv,
		ASLTLSEndpoint: aslEndpoint,
	}
}

func (srv *ASLServer) ListenAndServeASLTLS() error {
	// Parse the address and port from srv.Addr (inherited from http.Server)
	address := srv.Addr
	if address == "" {
		address = ":http" // Use the default port if none is specified
	}

	// Create the TCP Listener using the provided address from srv.Addr
	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", address, err)
	}

	aslListener := &aslListener.ASLListener{
		Endpoint: srv.ASLTLSEndpoint,
		Listener: tcpListener,
		Logger:   logging.NewLogger(srv.Logger),
		Debug:    srv.DebugLog,
	}

	log.Printf("\033[1;32mStarting ASL server on %s\033[0m", address)

	// Serve the HTTP requests using the custom ASL listener
	return srv.Serve(aslListener)
}
