package wolfSSL

// #cgo CFLAGS: -g -Wall -I../../config/include -I./config/include/wolfssl
// #cgo LDFLAGS: -L../../config/lib -lkritis3m_pki_server
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
// #ifdef NO_PSK
// typedef unsigned int (*pskCb)();
// int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint) {
//      return -174;
// }
// void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx, pskCb cb) {}
// #endif
// #ifndef WOLFSSL_DTLS
// WOLFSSL_METHOD*  wolfDTLSv1_2_server_method(void) {
//      return NULL;
// }
// WOLFSSL_METHOD*  wolfDTLSv1_2_client_method(void) {
//      return NULL;
// }
// void* wolfSSL_dtls_create_peer(int port, char* ip) {
//      return NULL;
// }
// int wolfSSL_dtls_free_peer(void* addr) {
//      return -174;
// }
// #endif
// #ifndef WOLFSSL_DTLS13
// WOLFSSL_METHOD*  wolfDTLSv1_3_server_method(void) {
//      return NULL;
// }
// WOLFSSL_METHOD*  wolfDTLSv1_3_client_method(void) {
//      return NULL;
// }
// #endif
import "C"
import (
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"
)

type WOLFSSL_CTX C.struct_WOLFSSL_CTX
type WOLFSSL C.struct_WOLFSSL
type WolfSSLConn struct {
	conn net.Conn
	ssl  *WOLFSSL
}
type METHOD C.struct_WOLFSSL_METHOD

type Method struct {
  Name string
}

const SSL_FILETYPE_PEM = 1
const WOLFSSL_SUCCESS = 1

func WolfSSL_get_error(ssl *WOLFSSL, ret int) int {
	return int(C.wolfSSL_get_error((*C.struct_WOLFSSL)(ssl), C.int(ret)))
}

func WolfSSL_ERR_error_string(ret int, data []byte) string {
	return C.GoString(C.wolfSSL_ERR_error_string(C.ulong(ret), (*C.char)(unsafe.Pointer(&data[0]))))
}

func WolfSSL_Init() {
	C.wolfSSL_Init()
}

func WolfSSL_Debugging_ON() {
	C.wolfSSL_Debugging_ON()
}

func WolfSSL_Cleanup() {
	C.wolfSSL_Cleanup()
}

func WolfSSL_CTX_new(method *C.struct_WOLFSSL_METHOD) *C.struct_WOLFSSL_CTX {
	return C.wolfSSL_CTX_new(method)
}

func WolfSSL_CTX_free(ctx *WOLFSSL_CTX) {
	C.wolfSSL_CTX_free((*C.struct_WOLFSSL_CTX)(ctx))
}

func WolfSSL_CTX_set_cipher_list(ctx *C.struct_WOLFSSL_CTX, list string) int {
	c_list := C.CString(list)
	defer C.free(unsafe.Pointer(c_list))
	return int(C.wolfSSL_CTX_set_cipher_list(ctx, c_list))
}

func WolfSSL_new(ctx *WOLFSSL_CTX) *WOLFSSL {
	return (*WOLFSSL)(C.wolfSSL_new((*C.struct_WOLFSSL_CTX)(ctx)))
}

func WolfSSL_connect(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_connect(ssl))
}

func WolfSSL_shutdown(ssl *WOLFSSL) {
	C.wolfSSL_shutdown((*C.struct_WOLFSSL)(ssl))
}

func WolfSSL_free(ssl *WOLFSSL) {
	C.wolfSSL_free((*C.struct_WOLFSSL)(ssl))
}

func WolfTLSv1_2_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_2_server_method()
}

func WolfTLSv1_2_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_2_client_method()
}

func WolfTLSv1_3_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_3_server_method()
}

func WolfTLSv1_3_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_3_client_method()
}

func WolfDTLSv1_2_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLSv1_2_server_method()
}

func WolfDTLSv1_2_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLSv1_2_client_method()
}

func WolfDTLSv1_3_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLSv1_3_server_method()
}

func WolfDTLSv1_3_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfDTLSv1_3_client_method()
}

func WolfSSL_dtls_create_peer(port int, ip string) unsafe.Pointer {
	c_ip := C.CString(ip)
	defer C.free(unsafe.Pointer(c_ip))
	return C.wolfSSL_dtls_create_peer(C.int(port), c_ip)
}

func WolfSSL_dtls_set_peer(ssl *C.struct_WOLFSSL, addr unsafe.Pointer, peerSz int) int {
	return int(C.wolfSSL_dtls_set_peer(ssl, addr, C.uint(peerSz)))
}

func WolfSSL_dtls_free_peer(addr unsafe.Pointer) int {
	return int(C.wolfSSL_dtls_free_peer(addr))
}

func WolfSSL_CTX_set_psk_server_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_psk_server_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_client_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_psk_client_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_server_tls13_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_psk_server_tls13_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_set_psk_client_tls13_callback(ctx *C.struct_WOLFSSL_CTX, cb unsafe.Pointer) {
	C.wolfSSL_CTX_set_psk_client_tls13_callback(ctx, (*[0]byte)(cb))
}

func WolfSSL_CTX_use_psk_identity_hint(ctx *C.struct_WOLFSSL_CTX, hint string) int {
	c_hint := C.CString(hint)
	defer C.free(unsafe.Pointer(c_hint))
	return int(C.wolfSSL_CTX_use_psk_identity_hint(ctx, c_hint))
}

func WolfSSL_CTX_load_verify_locations(ctx *C.struct_WOLFSSL_CTX, cert string,
	path []byte) int {
	cert_file := C.CString(cert)
	defer C.free(unsafe.Pointer(cert_file))
	/* TODO: HANDLE NON NIL PATH */
	return int(C.wolfSSL_CTX_load_verify_locations(ctx, cert_file,
		(*C.char)(unsafe.Pointer(nil))))
}

func WolfSSL_CTX_use_certificate_file(ctx *C.struct_WOLFSSL_CTX, cert string,
	format int) int {
	cert_file := C.CString(cert)
	defer C.free(unsafe.Pointer(cert_file))
	return int(C.wolfSSL_CTX_use_certificate_file(ctx, cert_file, C.int(format)))
}

func WolfSSL_CTX_use_PrivateKey_file(ctx *C.struct_WOLFSSL_CTX, key string,
	format int) int {
	key_file := C.CString(key)
	defer C.free(unsafe.Pointer(key_file))
	return int(C.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, C.int(format)))
}

func WolfSSL_set_fd(ssl *WOLFSSL, fd int) error {
	ret := int(C.wolfSSL_set_fd((*C.struct_WOLFSSL)(ssl), C.int(fd)))
	if ret != WOLFSSL_SUCCESS {
		WolfSSL_get_error(ssl, ret)
		message := make([]byte, 256)
		WolfSSL_ERR_error_string(ret, message)
		return fmt.Errorf("Error: %s", string(message))
	}
	return nil
}

func WolfSSL_accept(ssl *WOLFSSL) int {
	return int(C.wolfSSL_accept((*C.struct_WOLFSSL)(ssl)))
}

func WolfSSL_read(ssl *WOLFSSL, data []byte, sz uintptr) int {
	return int(C.wolfSSL_read((*C.struct_WOLFSSL)(ssl), unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_write(ssl *WOLFSSL, data []byte, sz uintptr) int {
	return int(C.wolfSSL_write((*C.struct_WOLFSSL)(ssl), unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_get_cipher_name(ssl *C.struct_WOLFSSL) string {
	return C.GoString(C.wolfSSL_get_cipher_name(ssl))
}

func WolfSSL_get_version(ssl *C.struct_WOLFSSL) string {
	return C.GoString(C.wolfSSL_get_version(ssl))
}

func WolfSSL_lib_version() string {
	return C.GoString(C.wolfSSL_lib_version())
}

func (w *WolfSSLConn) Read(b []byte) (int, error) {
	ret := WolfSSL_read(w.ssl, b, uintptr(len(b)))
	if ret < 0 {
		return int(ret), fmt.Errorf("WolfSSL_read failed")
	}
	return int(ret), nil
}

func (w *WolfSSLConn) Write(b []byte) (int, error) {
	ret := WolfSSL_write(w.ssl, b, uintptr(len(b)))
	if ret < 0 {
		return int(ret), fmt.Errorf("WolfSSL_write failed")
	}
	return int(ret), nil
}

func (w *WolfSSLConn) Close() error {
	WolfSSL_shutdown(w.ssl)
	WolfSSL_free(w.ssl)
	return w.conn.Close()
}

func (w *WolfSSLConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *WolfSSLConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *WolfSSLConn) SetDeadline(t time.Time) error {
	return w.conn.SetDeadline(t)
}

func (w *WolfSSLConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *WolfSSLConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

func InitWolfSSL(certFile, keyFile string, debug bool, method Method) *WOLFSSL_CTX {
	WolfSSL_Init()
	if debug {
		WolfSSL_Debugging_ON()
	}

  var ctx *C.struct_WOLFSSL_CTX
  switch method.Name {
    case "TLSv1.2":
      fmt.Println("TLSv1.2")
      ctx = WolfSSL_CTX_new(WolfTLSv1_2_server_method())
      if ctx == nil {
        panic("Failed to create WolfSSL context")
      }
    case "TLSv1.3":
      fmt.Println("TLSv1.3")
      ctx = WolfSSL_CTX_new(WolfTLSv1_3_server_method())
      if ctx == nil {
        panic("Failed to create WolfSSL context")
      }
    default:
      panic("Invalid method")
  }


	if WolfSSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) != 1 {
		panic("Failed to load server certificate")
	}
	if WolfSSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) != 1 {
		panic("Failed to load server private key")
	}

	WolfSSL_set_callbaks(ctx)

	return (*WOLFSSL_CTX)(ctx)
}

func HandleWolfSSLConnection(ctx *WOLFSSL_CTX, conn net.Conn) (*WolfSSLConn, error) {
	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve file descriptor: %v", err)
	}
	defer file.Close()

	fd := int(file.Fd())
	ssl := WolfSSL_new(ctx)
	if ssl == nil {
		log.Fatalf("Failed to create WolfSSL connection")
		return nil, fmt.Errorf("Failed to create WolfSSL connection\n")
	}

	if WolfSSL_set_fd(ssl, fd) != nil {
		WolfSSL_free(ssl)
		log.Fatalf("Failed to set file descriptor: %v", err)
		return nil, fmt.Errorf("Failed to set file descriptor: %v\n", err)
	}

	go func() {
		ret := WolfSSL_accept(ssl)
		if ret != WOLFSSL_SUCCESS {
			errCode := WolfSSL_get_error(ssl, ret)
			message := make([]byte, 256)
			WolfSSL_ERR_error_string(errCode, message)
			log.Fatalf("Failed to establish TLS connection: %s", string(message))
			WolfSSL_free(ssl)
		}
	}()

	return &WolfSSLConn{conn: conn, ssl: ssl}, nil
}
