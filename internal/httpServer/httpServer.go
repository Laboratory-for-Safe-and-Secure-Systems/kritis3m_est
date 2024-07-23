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
	"strconv"
	"strings"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
	"github.com/ayham/est"
)

type ASLHTTPServer struct {
	ASLEndpoint *asl.ASLEndpoint
	Listener    net.Listener
	Handler     http.Handler
	Logger      est.Logger
}

type CustomWriterFunc func(data []byte) (int, error)

// ServeTLS handles incoming connections using custom TLS
func (s *ASLHTTPServer) ServeTLS() {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			s.Logger.Errorf("Failed to accept connection: %v", err)
			return
		}
		s.handleConnection(conn)
	}
}

func (s *ASLHTTPServer) readRequest(aslSession *asl.ASLSession, buffer []byte, logger est.Logger) (*http.Request, error) {
	const (
		maxBufferSize     = 10 * 1024 * 1024 // 10MB max request size
		receiveBufferSize = 4096             // Increased from 1024 for efficiency
	)

	var (
		contentLength int
		headersParsed bool
		method        string
		hasBody       bool
		totalRead     int
	)

	for {
		if len(buffer) > maxBufferSize {
			return nil, fmt.Errorf("request too large: exceeded %d bytes", maxBufferSize)
		}

		wolfsslBuffer := make([]byte, receiveBufferSize)
		n, err := asl.ASLReceive(aslSession, wolfsslBuffer)
		if err != nil {
			if err == io.EOF {
				break // Connection closed
			}
			return nil, fmt.Errorf("failed to receive data: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("received 0 bytes: connection may have been closed")
		}

		buffer = append(buffer, wolfsslBuffer[:n]...)
		totalRead += n
		logger.Infow("Received data", "totalRead", totalRead, "n", n)

		if !headersParsed {
			headerEndIndex := bytes.Index(buffer, []byte("\r\n\r\n"))
			if headerEndIndex != -1 {
				headers := buffer[:headerEndIndex]
				headerLines := bytes.Split(headers, []byte("\r\n"))
				if len(headerLines) == 0 {
					return nil, fmt.Errorf("no headers found in request")
				}

				requestLine := string(headerLines[0])
				parts := strings.Fields(requestLine)
				if len(parts) < 3 {
					return nil, fmt.Errorf("invalid request line: %s", requestLine)
				}
				method = parts[0]

				switch method {
				case "POST", "PUT", "PATCH":
					hasBody = true
				case "GET", "HEAD", "DELETE", "OPTIONS", "TRACE":
					hasBody = false
				default:
					return nil, fmt.Errorf("unsupported HTTP method: %s", method)
				}

				for _, line := range headerLines[1:] {
					if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
						lengthStr := strings.TrimSpace(string(bytes.TrimPrefix(line, []byte("Content-Length:"))))
						parsedLength, err := strconv.Atoi(lengthStr) // Changed from ParseInt to Atoi
						if err != nil {
							return nil, fmt.Errorf("invalid Content-Length value: %w", err)
						}
						if parsedLength < 0 {
							return nil, fmt.Errorf("negative Content-Length: %d", parsedLength)
						}
						contentLength = parsedLength
						logger.Infof("Content-Length: %d", contentLength)
						break
					}
				}
				headersParsed = true
			}
		}

		if headersParsed {
			headerEndIndex := bytes.Index(buffer, []byte("\r\n\r\n"))
			if headerEndIndex != -1 {
				bodyStart := headerEndIndex + 4
				bodyLength := int(len(buffer) - bodyStart)

				if hasBody {
					if contentLength == 0 {
						return nil, fmt.Errorf("Content-Length header missing for %s request", method)
					}
					if bodyLength >= contentLength {
						break
					}
				} else if bodyLength > 0 {
					return nil, fmt.Errorf("unexpected body for %s request", method)
				} else {
					break
				}
			}
		}
	}

	buf := bufio.NewReader(bytes.NewReader(buffer))
	req, err := http.ReadRequest(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP request: %w", err)
	}

	wolfsslSession := asl.GetWolfSSLSession(aslSession)
	peerCert, err := asl.WolfSSL_get_peer_certificate(wolfsslSession)
	if err != nil {
		logger.Errorf("Failed to get peer certificate: %v", err)
	}

	req.TLS = &tls.ConnectionState{
		HandshakeComplete: true,
	}
	if peerCert != nil {
		req.TLS.PeerCertificates = []*x509.Certificate{peerCert}
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	return req, nil
}

func (s *ASLHTTPServer) handleConnection(conn net.Conn) {
	logger := s.Logger
	handler := s.Handler
	aslEndpoint := s.ASLEndpoint

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
		logger.Errorf("%v", err)
		return
	}

	buffer := make([]byte, 0)
	req, err := s.readRequest(aslSession, buffer, logger)
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
