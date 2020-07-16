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

#include "ssl.h"
#include "uget.h"

/*
 * Translates OpenSSL error code/status to human readable text.
 * Skips prototol (hacking) errors, connection reset, and the
 * odd cases where SSL_ERROR_SYSCALL and errno is unset.
 */
static int status(struct conn *c, int rc)
{
	char errmsg[80] = { 0 };

	if (rc > 0)
		return 0;

	warnx("status: %d", rc);
	rc = SSL_get_error(c->ssl, rc);
	warnx("SSL_get_error => %d", rc);
	switch (rc) {
	case SSL_ERROR_SSL:	          /* rc = 1 */
		errno = EPROTO;
		goto leave;

	case SSL_ERROR_WANT_READ:         /* rc = 2 */
	case SSL_ERROR_WANT_WRITE:        /* rc = 3 */
	case SSL_ERROR_WANT_X509_LOOKUP:  /* rc = 4 */
	case SSL_ERROR_WANT_CONNECT:      /* rc = 7 */
	case SSL_ERROR_WANT_ACCEPT:       /* rc = 8 */
		errno = EAGAIN;
		break;

	case SSL_ERROR_SYSCALL:	          /* rc = 5 */
		/* errno set already. */
		if (errno != 0 && errno != ECONNRESET && errno != EPROTO)
			snprintf(errmsg, sizeof(errmsg), "%s", strerror(errno));
		goto leave;

	default:
		errno = EINVAL;
		break;
	}

	if (*errmsg) {
		snprintf(errmsg, sizeof(errmsg), "%s, code %d",
			 ERR_reason_error_string(rc) ?: "unknown error", rc);
	}
leave:
	printf("%s\n", errmsg);
	return -1;
}

int ssl_init(struct conn *c)
{
	OpenSSL_add_all_algorithms();     /* Load cryptos, et.al. */
	SSL_load_error_strings();         /* Bring in and register error messages */

	c->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!c->ssl_ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* POODLE + BEAST, only allow TLSv1.1 or later */
#ifndef OPENSSL_NO_EC
	SSL_CTX_set_options(c->ssl_ctx, SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE
			    | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1
			    | SSL_OP_NO_COMPRESSION);
#else
	SSL_CTX_set_options(c->ssl_ctx, SSL_OP_SINGLE_DH_USE
			    | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1
			    | SSL_OP_NO_COMPRESSION);
#endif

	return 0;
}

int ssl_exit(struct conn *c)
{
	SSL_CTX_free(c->ssl_ctx);
	return 0;
}

int ssl_open(struct conn *c)
{
	c->ssl = SSL_new(c->ssl_ctx);
	SSL_set_fd(c->ssl, c->sd);

	if (status(c, SSL_connect(c->ssl)))
		return -1;

	return 0;
}

int ssl_close(struct conn *c)
{
	SSL_free(c->ssl);
	return 0;
}

int ssl_send(struct conn *c, char *buf, size_t len)
{
	return status(c, SSL_write(c->ssl, buf, len));
}

char *ssl_recv(struct conn *c, char *buf, size_t len)
{
	int num;

	num = SSL_read(c->ssl, buf, len - 1);
	if (num <= 0 && status(c, num))
		return NULL;
	buf[num] = 0;
	c->len = num;
	
	return buf;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
