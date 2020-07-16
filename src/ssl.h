/* Really stupid get-file-over-http program/function
 *
 * Copyright (c) 2019-2020  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.a
 */

#ifndef UGET_SSL_H_
#define UGET_SSL_H_

#include "config.h"
#include "uget.h"

#ifdef ENABLE_SSL
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int   ssl_init  (struct conn *c);
int   ssl_exit  (struct conn *c);

int   ssl_open  (struct conn *c);
int   ssl_close (struct conn *c);

int   ssl_send  (struct conn *c, char *buf, size_t len);
char *ssl_recv  (struct conn *c, char *buf, size_t len);

#else /* fallback to trigger error */

static inline int   ssl_init  (struct conn *c) { (void)c; return -1; }
static inline int   ssl_exit  (struct conn *c) { (void)c; return -1; }

static inline int   ssl_open  (struct conn *c) { (void)c; errno = EPROTONOSUPPORT; return -1; }
static inline int   ssl_close (struct conn *c) { (void)c; return -1; }

static inline int   ssl_send  (struct conn *c, char *buf, size_t len) { (void)c; (void)buf, (void)len; return -1; }
static inline char *ssl_recv  (struct conn *c, char *buf, size_t len) { (void)c; (void)buf, (void)len; return NULL; }

#endif /* ENABLE_SSL */
#endif /* UGET_SSL_H_ */
