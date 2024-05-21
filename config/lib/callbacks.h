#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <wolfssl/ssl.h>

int wolfssl_read_callback(WOLFSSL *session, char *buffer, int size,
                                 void *ctx);
int wolfssl_write_callback(WOLFSSL *session, char *buffer, int size,
                                  void *ctx);

#endif // CALLBACKS_H
