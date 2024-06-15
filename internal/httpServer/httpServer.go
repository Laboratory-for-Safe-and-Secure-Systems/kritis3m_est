package httpserver

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
	"github.com/ayham/est"
)

var logger est.Logger

type CustomWriterFunc func(data []byte) (int, error)

// ServeCustomTLS handles incoming connections using custom TLS
func ServeCustomTLS(aslEndpoint *asl.ASLEndpoint, listener net.Listener, handler http.Handler) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(aslEndpoint, conn, handler)
	}
}

func readRequest(aslSession *asl.ASLSession, buffer []byte) (*http.Request, error) {
	for {
		wolfsslBuffer := make([]byte, 1024)

		// check the last 4 bytes of the buffer to see if it is the end of the request
		if len(buffer) >= 4 {
			if string(buffer[len(buffer)-4:]) == "\r\n\r\n" {
				break
			}
		}

		n, err := asl.ASLReceive(aslSession, wolfsslBuffer)
		if err != nil {
			logger.Errorf("Failed to receive data: %v", err)
			return nil, err
		}

		// append the data to the buffer with the correct length without the extra bytes
		buffer = append(buffer, wolfsslBuffer[:n]...)

	}

	// Read the HTTP request from the wolfSSLBuffer
	buf := bufio.NewReader(bytes.NewReader(buffer))

	// Parse the HTTP request
	req, err := http.ReadRequest(buf)
	if err != nil {
		logger.Errorf("Failed to read request: %v", err)
		return nil, err
	}

  // TODO: in case no Peer Certificate and MTLS is set to true what should happen
  // current behavior is segmentation fault (null pointer somewhere)
	// Add TLS connection to the request
	wolfsslSession := asl.GetWolfSSLSession(aslSession)
	perrCert, err := asl.WolfSSL_get_peer_certificate(wolfsslSession)
	if err != nil && perrCert != nil {
		logger.Errorf("Failed to get peer certificate: %v", err)
		return nil, err
	} else if perrCert == nil {
		// nothing to do
	} else {
		// Add tls connection to the request
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{perrCert},
		}
	}

	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset the body after reading
	err = req.Body.Close()
	if err != nil {
		logger.Errorf("Failed to close request body: %v", err)
		return nil, err
	}

	return req, nil
}

func handleConnection(aslEndpoint *asl.ASLEndpoint, conn net.Conn, handler http.Handler) {
	defer conn.Close()

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		logger.Errorf("Failed to get file descriptor: %v", err)
		return
	}

	fd := file.Fd()
	aslSession := asl.ASLCreateSession(aslEndpoint, int(fd))
	defer file.Close()

	err = asl.ASLHandshake(aslSession)
	if err != nil {
		logger.Errorf("Failed to handshake: %v", err)
		return
	}

	buffer := make([]byte, 0)
	req, err := readRequest(aslSession, buffer)
	if err != nil {
		logger.Errorf("Failed to read request: %v", err)
		return
	}

	// Set the remote address
	req.RemoteAddr = conn.RemoteAddr().String()
	req.URL.Scheme = "https"

	// Define the custom write function
	customWrite := func(data []byte) (int, error) {
		err := asl.ASLSend(aslSession, data)
		if err != nil {
			return 0, err
		}
		return len(data), nil
	}

	// Create a custom response writer
	rw := &responseWriter{
		header:      http.Header{},
		customWrite: customWrite,
	}

	// Serve the request
	handler.ServeHTTP(rw, req)

	// Flush the response
	rw.Flush()
	asl.ASLCloseSession(aslSession)
	asl.ASLFreeSession(aslSession)
}

// responseWriter is a custom implementation of http.ResponseWriter
type responseWriter struct {
	header      http.Header
	buffer      bytes.Buffer
	status      int
	wroteHeader bool
	customWrite CustomWriterFunc
}

func (rw *responseWriter) Header() http.Header {
	return rw.header
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.buffer.Write(data)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.wroteHeader {
		logger.Infof("ResponseWriter.WriteHeader called multiple times")
		return
	}
	rw.status = statusCode
	rw.wroteHeader = true
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	rw.buffer.WriteString(statusLine)

	for key, values := range rw.header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			rw.buffer.WriteString(headerLine)
		}
	}
	rw.buffer.WriteString("\r\n")
}

func (rw *responseWriter) Flush() error {
	if rw.wroteHeader {
		_, err := rw.customWrite(rw.buffer.Bytes())
		return err
	}
	return nil
}
