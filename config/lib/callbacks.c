#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfio.h>
#include "callbacks.h"

#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT *wolfssl_heap;
extern uint8_t *wolfsslMemoryBuffer;
extern size_t wolfsslMemoryBufferSize;
#else
#define wolfssl_heap NULL
#endif

enum connection_state {
  CONNECTION_STATE_NOT_CONNECTED,
  CONNECTION_STATE_HANDSHAKE,
  CONNECTION_STATE_CONNECTED,
};

/* Data structure for an active session */
typedef struct wolfssl_session {
  WOLFSSL *session;
  enum connection_state state;

  struct {
    struct timespec start_time;
    struct timespec end_time;
    uint32_t txBytes;
    uint32_t rxBytes;
  } handshake_metrics_priv;
} wolfssl_session;

int wolfssl_read_callback(WOLFSSL *wolfssl, char *buffer, int size,
                                 void *ctx) {
  int socket = wolfSSL_get_fd(wolfssl);
  wolfssl_session *session = (wolfssl_session *)ctx;

  int ret = recv(socket, buffer, size, 0);

  if (ret == 0) {
    // LOG_WRN("connection closed by peer");
    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
  } else if (ret < 0) {
    int error = errno;
    // LOG_WRN("recv error: %d", error);
    if ((error == EAGAIN) || (error == EWOULDBLOCK))
      return WOLFSSL_CBIO_ERR_WANT_READ;
    else
      return WOLFSSL_CBIO_ERR_GENERAL;
  }

  /* Update handshake metrics */
  if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE) {
    session->handshake_metrics_priv.rxBytes += ret;
  }

  return ret;
}

int wolfssl_write_callback(WOLFSSL *wolfssl, char *buffer, int size,
                                  void *ctx) {
  int socket = wolfSSL_get_fd(wolfssl);
  wolfssl_session *session = (wolfssl_session *)ctx;

  int ret = send(socket, buffer, size, 0);

  if (ret < 0) {
    int error = errno;
    // LOG_WRN("send error: %d", error);
    if ((error == EAGAIN) || (error == EWOULDBLOCK))
      return WOLFSSL_CBIO_ERR_WANT_WRITE;
    else if (error == ECONNRESET)
      return WOLFSSL_CBIO_ERR_CONN_RST;
    else
      return WOLFSSL_CBIO_ERR_GENERAL;
  }

  /* Update handshake metrics */
  if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE) {
    session->handshake_metrics_priv.txBytes += ret;
  }

  return ret;
}

