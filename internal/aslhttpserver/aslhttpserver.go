package aslhttpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
)

// ASLServer struct that embeds http.Server and uses custom ASL TLS listener
type ASLServer struct {
	*http.Server
	ASLTLSEndpoint *asl.ASLEndpoint // Custom ASL Endpoint configuration
}

type contextKey string

const TLSStateKey contextKey = "tlsState"

// Constructor for ASLServer
func NewASLServer(addr string, handler http.Handler, endpointConfig *asl.EndpointConfig) *ASLServer {
	// Initialize http.Server
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Set the ConnContext function
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if aslConn, ok := c.(*ASLConn); ok {
			ctx = context.WithValue(ctx, TLSStateKey, aslConn.TLSState)
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

// ASLConn wraps the TCPConn and ASLSession
type ASLConn struct {
	tcpConn    *net.TCPConn
	aslSession *asl.ASLSession
	peerCert   *x509.Certificate // Store the peer's certificate
	TLSState   *tls.ConnectionState
}

func (c ASLConn) Read(b []byte) (n int, err error) {
	return asl.ASLReceive(c.aslSession, b)
}

func (c ASLConn) Write(b []byte) (n int, err error) {
	err = asl.ASLSend(c.aslSession, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c ASLConn) Close() error {
	asl.ASLCloseSession(c.aslSession)
	asl.ASLFreeSession(c.aslSession)
	return c.tcpConn.Close()
}

func (c ASLConn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

func (c ASLConn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

func (c ASLConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

func (c ASLConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

func (c ASLConn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

// Simulate a TLS connection state
func (c *ASLConn) simulateTLSState() {
	// Capture and store the peer certificate (if available)
	wolfssl := asl.GetWolfSSLSession(c.aslSession)
	peerCert, err := asl.WolfSSL_get_peer_certificate(wolfssl)
	if err == nil {
		c.peerCert = peerCert
	} else {
		log.Printf("Failed to get peer certificate: %v", err)
	}

	// Populate tls.ConnectionState
	if c.peerCert != nil {
		c.TLSState = &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{c.peerCert},
		}
	}
}

// ASLListener wraps a net.TCPListener and handles ASL sessions
type ASLListener struct {
	tcpListener *net.TCPListener
	endpoint    *asl.ASLEndpoint
}

// Accept accepts a new connection and wraps it with ASLSession
func (l ASLListener) Accept() (net.Conn, error) {
	c, err := l.tcpListener.Accept()
	if err != nil {
		return nil, err
	}

	tcpConn := c.(*net.TCPConn)
	file, _ := tcpConn.File()
	fd := int(file.Fd())

	session := asl.ASLCreateSession(l.endpoint, fd)
	if session == nil {
		return nil, fmt.Errorf("failed to create ASL session")
	}

	aslConn := &ASLConn{
		tcpConn:    tcpConn,
		aslSession: session,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
		tcpConn.Close()
		log.Printf("ASL handshake failed: %v", err)
	}

	// Simulate a TLS connection state
	aslConn.simulateTLSState()

	return aslConn, nil
}

// Close closes the listener
func (l ASLListener) Close() error {
	return l.tcpListener.Close()
}

// Addr returns the listener's network address
func (l ASLListener) Addr() net.Addr {
	return l.tcpListener.Addr()
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

	aslListener := &ASLListener{
		tcpListener: tcpListener.(*net.TCPListener),
		endpoint:    srv.ASLTLSEndpoint,
	}

	// Log the server start event
	log.Printf("ASLServer listening on %s", srv.Addr)

	// Serve the HTTP requests using the custom ASL listener
	return srv.Serve(aslListener)
}
