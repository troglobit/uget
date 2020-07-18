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
	static char errmsg[80];

	c->errmsg = NULL;
	if (rc > 0)
		return 0;

	rc = SSL_get_error(c->ssl, rc);
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
			c->errmsg = strerror(errno);
		goto leave;

	default:
		errno = EINVAL;
		break;
	}

	if (c->errmsg) {
		snprintf(errmsg, sizeof(errmsg), "SSL %s, code %d",
			 ERR_reason_error_string(rc) ?: "unknown error", rc);
		c->errmsg = errmsg;
	}

leave:
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

static int ssl_set_ca_location(struct conn *c)
{
	char *cafile = "built-in defaults (override with SSL_CERT_DIR environment variable)";
	int ret;

	/* A user defined CA PEM bundle overrides any built-ins or fall-backs */
	if (cacert) {
		ret = SSL_CTX_load_verify_locations(c->ssl_ctx, cacert, NULL);
		goto done;
	}

	ret = SSL_CTX_set_default_verify_paths(c->ssl_ctx);
	if (ret < 1) {
		cafile = CAFILE1;
		ret = SSL_CTX_load_verify_locations(c->ssl_ctx, cafile, NULL);
	}
	if (ret < 1) {
		cafile = CAFILE2;
		ret = SSL_CTX_load_verify_locations(c->ssl_ctx, cafile, NULL);
	}
done:
	if (ret < 1)
		return 1;

	vrb("* Successfully set certificate verify location:");
	vrb("*  CAfile: %s", cafile);

	return 0;
}

int ssl_open(struct conn *c)
{
	X509 *cert;
	BIO *out;

	/* Try to figure out location of trusted CA certs on system */
	if (ssl_set_ca_location(c))
		return -1;

	c->ssl = SSL_new(c->ssl_ctx);
	if (!c->ssl)
		return -1;

	SSL_set_fd(c->ssl, c->sd);

	/* Enable automatic hostname checks, allow wildcard certs */
	SSL_set_hostflags(c->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	SSL_set1_host(c->ssl, c->server);
	SSL_set_tlsext_host_name(c->ssl, c->server);

	SSL_CTX_set_verify(c->ssl_ctx, c->strict ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify_depth(c->ssl_ctx, 150);

	if (status(c, SSL_connect(c->ssl))) {
		fprintf(stderr, "* Failed SSL connection: %s\n", c->errmsg);
		return -1;
	}

	vrb("* SSL connection using %s / %s", SSL_get_cipher_version(c->ssl), SSL_get_cipher_name(c->ssl));

	cert = SSL_get_peer_certificate(c->ssl);
	if (!cert) {
		fprintf(stderr, "* Failed querying %s for certificate", c->server);
		return -1;
	}

	if (verbose) {
		out = BIO_new_fp(stdout, BIO_NOCLOSE);

		BIO_puts(out, "* Server certificate:");
		BIO_puts(out, "\n*  subject: ");
		X509_NAME_print(out, X509_get_subject_name(cert), 0);

		BIO_puts(out, "\n*  start date: ");
		ASN1_TIME_print(out, X509_get0_notBefore(cert));
		BIO_puts(out, "\n*  expire date: ");
		ASN1_TIME_print(out, X509_get0_notAfter(cert));

		BIO_puts(out, "\n*  subjectAltName: host \"");
		BIO_puts(out, c->server);
		BIO_puts(out, "\" ");
		if (SSL_get_verify_result(c->ssl) == X509_V_OK) {
			BIO_puts(out, "matched cert's \"");
			BIO_puts(out, SSL_get0_peername(c->ssl) ?: "");
			BIO_puts(out, "\"");
		} else
			BIO_puts(out, "not found in cert!");

		BIO_puts(out, "\n*  issuer: ");
		X509_NAME_print(out, X509_get_issuer_name(cert), 0);

		BIO_free_all(out);
	}

	if (SSL_get_verify_result(c->ssl) == X509_V_OK)
		vrb("\n*  SSL certificate verify OK.");

	X509_free(cert);

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
