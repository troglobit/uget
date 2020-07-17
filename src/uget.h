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

#ifndef UGET_H_
#define UGET_H_

#include "config.h"

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#define dbg(fmt, args...) if (verbose > 1) printf(fmt "\n", ##args)
#define vrb(fmt, args...) if (verbose > 0) printf(fmt "\n", ##args)

struct conn {
	char     *cmd;		/* GET/HEAD/POST */
	char     *server;
	uint16_t  port;
	char     *location;

	char      host[INET6_ADDRSTRLEN];

	int       redirect;
	char      redirect_url[256];

	int       sd;
	int       content_len;

	char     *buf;		/* At least BUFSIZ xfer buffer */
	size_t    len;

	int       do_ssl;	/* http or https connection */
	void     *ssl;
	void     *ssl_ctx;

	char     *errmsg;
};

extern int verbose;

#endif /* UGET_H_ */
