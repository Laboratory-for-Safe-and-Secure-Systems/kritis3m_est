package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	wolfSSL "github.com/ayham/est/internal/go-wolfssl"
)

/* Connection configuration constants */
const (
	CONN_HOST = "localhost"
	CONN_PORT = "11111"
	CONN_TYPE = "tcp"
)

func main() {
	/* Server Key and Certificate paths */
	CERT_FILE := "../est/certs/server_cert.pem"
	KEY_FILE := "../est/certs/server_key.pem"

	/* Initialize wolfSSL */
	method := wolfSSL.Method{Name: "TLSv1.3"}

  ctx := wolfSSL.InitWolfSSL(CERT_FILE, KEY_FILE, false, method)


	/* Listen for incoming connections */
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	/* Close the listener when the application closes */
	defer l.Close()
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	/* Listen for an incoming connection */
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				fmt.Println("Error accepting: ", err.Error())
				os.Exit(1)
			}
			/* Handle connections concurrently */
			go handleRequest(conn, (*wolfSSL.WOLFSSL_CTX)(ctx))
		}
	}()

	/* Wait for a signal to shutdown */
	got := <-sig
	fmt.Println("Received signal:", got)

	/* Shutdown wolfSSL */
	/* Free wolfSSL and wolfSSL_CTX objects */
	/* Cleanup wolfSSL_CTX object */
	wolfSSL.WolfSSL_CTX_free((*wolfSSL.WOLFSSL_CTX)(ctx))
	/* Cleanup the wolfSSL environment */
	wolfSSL.WolfSSL_Cleanup()
}

/* Handles incoming requests */
func handleRequest(conn net.Conn, ctx *wolfSSL.WOLFSSL_CTX) {
	/* Create a WOLFSSL object */
	ssl := wolfSSL.WolfSSL_new((*wolfSSL.WOLFSSL_CTX)(ctx))
	if ssl == nil {
		fmt.Println("WolfSSL_new Failed")
		os.Exit(1)
	}
	var ret int
	/* Retrieve file descriptor from net.Conn type */
	file, err := conn.(*net.TCPConn).File()
	fd := file.Fd()
	err = wolfSSL.WolfSSL_set_fd(ssl, int(fd))
	if err != nil {
		fmt.Println("Error: WolfSSL_set_fd Failed")
		os.Exit(1)
	}
	defer file.Close()

	/* Establish TLS connection */
	ret = wolfSSL.WolfSSL_accept(ssl)
	if ret != wolfSSL.WOLFSSL_SUCCESS {
		ret = wolfSSL.WolfSSL_get_error(ssl, ret)
		fmt.Println("Error: WolfSSL_accept Failed:", ret)
		message := make([]byte, 256)
		wolfSSL.WolfSSL_ERR_error_string(ret, message)
		fmt.Println("Error:", string(message))
		file.Close()
		return
	} else {
		fmt.Println("Client Successfully Connected!")
	}

	buf := make([]byte, 1000000)

	/* Receive then print the message from client */
	ret = wolfSSL.WolfSSL_read(ssl, buf, 100000)
	if ret == -1 {
		fmt.Println("WolfSSL_read failed")
	} else {
		fmt.Println("Client says:", string(buf))
	}

	/* Create the message and send to client */
	reply := []byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello World!\n")
	sz := uintptr(len(reply))

	ret = wolfSSL.WolfSSL_write(ssl, reply, sz)
	if uintptr(ret) != sz {
		fmt.Println("WolfSSL_write failed")
		os.Exit(1)
	}

	/* Close the connection */
	conn.Close()
	wolfSSL.WolfSSL_shutdown(ssl)
	wolfSSL.WolfSSL_free(ssl)
}
