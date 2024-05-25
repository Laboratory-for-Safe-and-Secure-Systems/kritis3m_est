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

	"github.com/ayham/est"
	wolfSSL "github.com/ayham291/go-wolfssl"
)

var logger est.Logger

type CustomWriterFunc func(data []byte) (int, error)

// ServeCustomTLS handles incoming connections using custom TLS
func ServeCustomTLS(ctx *wolfSSL.WOLFSSL_CTX, listener net.Listener, handler http.Handler) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(ctx, conn, handler)
	}
}

func readRequest(ssl *wolfSSL.WOLFSSL, buffer []byte) (*http.Request, error) {
	for {
		wolfsslBuffer := make([]byte, 1024)

		// check the last 4 bytes of the buffer to see if it is the end of the request
		if len(buffer) >= 4 {
			if string(buffer[len(buffer)-4:]) == "\r\n\r\n" {
				break
			}
		}

		n := wolfSSL.WolfSSL_read(ssl, wolfsslBuffer, uintptr(len(wolfsslBuffer)))

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

	// Add TLS connection to the request
	perrCert, err := wolfSSL.WolfSSL_get_peer_certificate(ssl)
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

func handleConnection(ctx *wolfSSL.WOLFSSL_CTX, conn net.Conn, handler http.Handler) {
	defer conn.Close()

	ssl := wolfSSL.WolfSSL_new(ctx)
	if ssl == nil {
		logger.Errorf("Failed to create new wolfSSL object")
		return
	}

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		logger.Errorf("Failed to get file descriptor: %v", err)
		return
	}

	fd := file.Fd()
	err = wolfSSL.WolfSSL_set_fd(ssl, int(fd))
	if err != nil {
		logger.Errorf("Failed to set file descriptor: %v", err)
		return
	}
	defer file.Close()

	ret := wolfSSL.WolfSSL_accept(ssl)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		ret = wolfSSL.WolfSSL_get_error(ssl, ret)
		logger.Errorf("Failed to accept connection: %v", ret)
		message := make([]byte, 64)
		wolfSSL.WolfSSL_ERR_error_string(ret, message)
		logger.Errorf("Error message: %s", message)
		file.Close()
		return
	}

	buffer := make([]byte, 0)
	req, err := readRequest(ssl, buffer)
	if err != nil {
		logger.Errorf("Failed to read request: %v", err)
		return
	}

	// Set the remote address
	req.RemoteAddr = conn.RemoteAddr().String()

	// Define the custom write function
	customWrite := func(data []byte) (int, error) {
		return wolfSSL.WolfSSL_write(ssl, data, uintptr(len(data))), nil
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
	wolfSSL.WolfSSL_shutdown(ssl)
	wolfSSL.WolfSSL_free(ssl)
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
