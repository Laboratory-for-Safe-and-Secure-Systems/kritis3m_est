package aslhttpclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
)

// ASLConn wraps the TCPConn and ASLSession (same as in the server)
type ASLConn struct {
	tcpConn    *net.TCPConn
	aslSession *asl.ASLSession
}

func (c *ASLConn) Read(b []byte) (n int, err error) {
	return asl.ASLReceive(c.aslSession, b)
}

func (c *ASLConn) Write(b []byte) (n int, err error) {
	err = asl.ASLSend(c.aslSession, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ASLConn) Close() error {
	asl.ASLCloseSession(c.aslSession)
	asl.ASLFreeSession(c.aslSession)
	return c.tcpConn.Close()
}

func (c *ASLConn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

func (c *ASLConn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

func (c *ASLConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

func (c *ASLConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

func (c *ASLConn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

// ASLTransport is a custom RoundTripper that uses ASL for TLS communication
type ASLTransport struct {
	Endpoint *asl.ASLEndpoint
	Dialer   *net.Dialer // Optional custom dialer for timeouts, etc.
}

// DialContext creates a custom ASL connection instead of using TLS
func (t *ASLTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Dial the TCP connection
	tcpConn, err := t.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Cast to TCPConn
	rawConn, ok := tcpConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast to *net.TCPConn")
	}

	// Set up ASL session using the file descriptor from the TCP connection
	file, _ := rawConn.File()
	fd := int(file.Fd())

	aslSession := asl.ASLCreateSession(t.Endpoint, fd)
	if aslSession == nil {
		return nil, fmt.Errorf("failed to create ASL session")
	}

	aslConn := &ASLConn{
		tcpConn:    rawConn,
		aslSession: aslSession,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
		return nil, fmt.Errorf("ASL handshake failed: %v", err)
	}

	// // Set a context for the handshake with a timeout
	// handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	// defer cancel()

	// // Perform ASL handshake
	// done := make(chan error, 1)
	// go func() {
	// 	done <- asl.ASLHandshake(aslConn.aslSession)
	// }()

	// select {
	// case <-handshakeCtx.Done():
	// 	rawConn.Close() // Ensure to close the connection if we timeout
	// 	return nil, fmt.Errorf("ASL handshake timed out")
	// case err := <-done:
	// 	if err != nil {
	// 		rawConn.Close()
	// 		return nil, fmt.Errorf("ASL handshake failed: %v", err)
	// 	}
	// }

	return aslConn, nil
}

// RoundTrip executes a single HTTP transaction
func (t *ASLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Handle "https" scheme manually with ASL
	if req.URL.Scheme == "https" {
		conn, err := t.DialContext(req.Context(), "tcp", req.URL.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to establish ASL connection: %v", err)
		}
		defer conn.Close()

		// Set a timeout for writing the request
		writeDeadline := time.Now().Add(5 * time.Second)
		err = conn.SetWriteDeadline(writeDeadline)
		if err != nil {
			return nil, fmt.Errorf("failed to set write deadline: %v", err)
		}

		// Send the HTTP request manually over the custom connection
		err = req.Write(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to write request: %v", err)
		}

		// Read the HTTP response
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %v", err)
		}

		return resp, nil
	}

	// Fallback for non-https schemes
	return http.DefaultTransport.RoundTrip(req)
}
