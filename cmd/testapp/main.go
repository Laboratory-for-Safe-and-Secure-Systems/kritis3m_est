package main

import "C"
import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"

	wolfSSL "github.com/ayham/est/internal/go-wolfssl"
)

type CustomWriterFunc func(data []byte) (int, error)

// CustomListener creates a TCP listener on the specified address
func CustomListener(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

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

func handleConnection(ctx *wolfSSL.WOLFSSL_CTX, conn net.Conn, handler http.Handler) {
	defer conn.Close()

	// Create a new wolfSSL object
	ssl := wolfSSL.WolfSSL_new(ctx)
	if ssl == nil {
		log.Println("WolfSSL_new Failed")
		return
	}

	// Retrieve file descriptor from net.Conn type
	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		log.Printf("Failed to get file descriptor: %v", err)
		return
	}
	fd := file.Fd()
	err = wolfSSL.WolfSSL_set_fd(ssl, int(fd))
	if err != nil {
		log.Printf("Failed to set file descriptor: %v", err)
		return
	}
	defer file.Close()

	// Establish TLS connection
	ret := wolfSSL.WolfSSL_accept(ssl)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		ret = wolfSSL.WolfSSL_get_error(ssl, ret)
		log.Printf("Failed to accept connection: %v", ret)
		message := make([]byte, 64)
		wolfSSL.WolfSSL_ERR_error_string(ret, message)
		log.Printf("Error: %s", string(message))
		file.Close()
		return
	}

	wolfsslBuffer := make([]byte, 100000)
	n := wolfSSL.WolfSSL_read(ssl, wolfsslBuffer, uintptr(len(wolfsslBuffer)))

	// Read the HTTP request from the wolfSSLBuffer
	buffer := bufio.NewReader(bytes.NewReader(wolfsslBuffer[:n]))

	// Parse the HTTP request
	req, err := http.ReadRequest(buffer)
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	// Define the custom write function
	customWrite := func(data []byte) (int, error) {
		// write the data to the connection using wolfSSL
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
		return
	}
	rw.status = statusCode
	rw.wroteHeader = true
	statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
  rw.header.Set("Content-Type", "text/plain")
	rw.buffer.WriteString(statusLine)
  
  // content-length is required for the response to be valid
  rw.header.Set("Content-Length", fmt.Sprintf("%d", rw.buffer.Len()))

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

func main() {
	CERT_FILE := "../est/certs/server_cert.pem"
	KEY_FILE := "../est/certs/server_key.pem"

	/* Initialize wolfSSL */
	method := wolfSSL.Method{Name: "TLSv1.3"}

	ctx := wolfSSL.InitWolfSSL(CERT_FILE, KEY_FILE, false, method)

	addr := ":8080"

	// Create a custom TCP listener
	tcpListener, err := CustomListener(addr)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	// Define your HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, test!"))
	})

	handler := http.DefaultServeMux

	// Start serving using the custom TLS library
	log.Printf("Serving on https://%s", addr)
	err = ServeCustomTLS(ctx, tcpListener, handler)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
