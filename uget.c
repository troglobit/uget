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
#include <sys/types.h>
#include <sys/socket.h>

#define dbg(fmt, args...) if (debug) warnx(fmt, ##args)

struct uget {
	char     *server;
	uint16_t  port;
	char     *location;

	char      host[20];
};

static int debug;

static int split(char *url, struct uget *ctx)
{
	char *ptr, *pptr;

	if (!url)
		return 1;

	ptr = strstr(url, "://");
	if (!ptr)
		ptr = url;
	else
		ptr += 3;
	ctx->server = ptr;

	ptr = strchr(ptr, ':');
	if (ptr) {
		*ptr++ = 0;
		pptr = ptr;
	} else {
		ptr = ctx->server;
		if (!strncmp(url, "http://", 7))
			pptr = "80";
		else
			pptr = "443";
	}

	ptr = strchr(ptr, '/');
	if (!ptr)
		ptr = "";
	else
		*ptr++ = 0;
	ctx->location = ptr;

	if (pptr)
		ctx->port = atoi(pptr);

	if (!ctx->server)
		return 1;

	dbg("Parsed URL: FROM %s PORT %d GET /%s", ctx->server, ctx->port, ctx->location);

	return 0;
}

static int nslookup(struct uget *ctx, struct addrinfo **result)
{
	struct addrinfo hints;
	char service[10];
	int rc;

	snprintf(service, sizeof(service), "%d", ctx->port);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags    = 0;
	hints.ai_protocol = 0;

	rc = getaddrinfo(ctx->server, service, &hints, result);
	if (rc) {
		warnx("Failed looking up %s:%s: %s", ctx->server, service, gai_strerror(rc));
		return -1;
	}

	return 0;
}

static int get(int sd, struct uget *ctx)
{
	struct pollfd pfd;
	ssize_t num;
	size_t len;
	char buf[256];

	len = snprintf(buf, sizeof(buf), "GET /%s HTTP/1.1\r\n"
		       "Host: %s:%d\r\n"
		       "Cache-Control: no-cache\r\n"
		       "Connection: close\r\n"
		       "Pragma: no-cache\r\n"
		       "Accept: text/xml, application/xml\r\n"
		       "User-Agent: " PACKAGE_NAME "/" PACAKGE_VERSION "\r\n"
		       "\r\n",
		       ctx->location, ctx->host, ctx->port);
	dbg("Sending request to %s:%d for /%s", ctx->host, ctx->port, ctx->location);
	dbg("HTTP request: %s", buf);

	num = send(sd, buf, len, 0);
	if (num < 0) {
		warn("Failed sending HTTP GET /%s to %s:%d", ctx->location, ctx->host, ctx->port);
		close(sd);
		return -1;
	}

	pfd.fd = sd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 1000) < 0) {
		warn("Server %s: %s", ctx->host, strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}

static int hello(struct uget *ctx, struct addrinfo *ai)
{
	struct sockaddr_in *sin;
	struct addrinfo *rp;
	int sd;

	for (rp = ai; rp != NULL; rp = rp->ai_next) {
		struct timeval timeout = { 0, 200000 };

		sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sd == -1)
			continue;

		/* Attempt to adjust recv timeout */
		if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
			warn("Failed setting recv() timeout");

		/* Attempt to connect to this address:port */
		if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* Success */

		sin = (struct sockaddr_in *)rp->ai_addr;
		inet_ntop(AF_INET, &sin->sin_addr, ctx->host, sizeof(ctx->host));
		warn("Failed connecting to %s:%d", ctx->host, ntohs(sin->sin_port));

		close(sd);
	}

	if (rp == NULL)
		return -1;

	sin = (struct sockaddr_in *)rp->ai_addr;
	inet_ntop(AF_INET, &sin->sin_addr, ctx->host, sizeof(ctx->host));

	return get(sd, ctx);
}

static char *bufgets(char *buf)
{
	static char *next = NULL;
	char *ptr;

	if (buf)
		next = buf;
	ptr = next;

	if (next) {
		char *eol = strstr(next, "\r\n");

		if (eol) {
			*eol = 0;
			next = eol + 2;
		} else
			next = NULL;
	}

	return ptr;
}

static char *token(char **buf)
{
	char *ptr = *buf;
	char *p;

	if (!buf || !ptr)
		return NULL;

	p = strpbrk(ptr, " \t\r\n");
	if (p) {
		*p++ = 0;
		*buf = p;
	}

	return ptr;

}

static char *parse_headers(char *buf)
{
	char version[8];
	char mesg[32];
	char *content;
	char *ptr, *p;
	int code = 0;

	/* Find start of content */
	content = strstr(buf, "\r\n\r\n");
	if (!content) {
		warnx("max header size");
		return NULL;
	}
	*content = 0;
	content += 4;

	ptr = bufgets(buf);
	if (!ptr) {
		warnx("no HTTP response code");
		return NULL;
	}
	dbg("HTTP response: %s", ptr);

	p = token(&ptr);
	if (p)
		snprintf(version, sizeof(version), "%s", p);
	p = token(&ptr);
	if (p)
		code = atoi(p);
	if (ptr)
		snprintf(mesg, sizeof(mesg), "%s", ptr);

	switch (code) {
	case 200:
		break;
	default:
		warnx("invalid response: %d %s", code, mesg);
		content = NULL;
		break;
	}

	while ((ptr = bufgets(NULL)))
		dbg("hdr: %s", ptr);

	return content;
}

static char *fetch(int sd, char *buf, size_t len)
{
	ssize_t num;

	num = recv(sd, buf, len - 1, 0);
	if (num > 0) {
		buf[num] = 0;
		return buf;
	}

	return NULL;
}

FILE *uget(char *url, char *buf, size_t len)
{
	struct uget ctx = { 0 };
	struct addrinfo *ai;
	FILE *fp;
	char *ptr;
	int sd;

	dbg("URL: %s", url);
	if (split(url, &ctx))
		return NULL;

	if (nslookup(&ctx, &ai))
		return NULL;

	sd = hello(&ctx, ai);
	freeaddrinfo(ai);
	if (-1 == sd)
		return NULL;

	dbg("Connected.");
	if (!fetch(sd, buf, len)) {
		warnx("no data");
	fail:
		shutdown(sd, SHUT_RDWR);
		close(sd);
		return NULL;
	}

	ptr = parse_headers(buf);
	if (!ptr)
		goto fail;

	fp = tmpfile();
	if (!fp) {
		warnx("failed creating tempfile");
		goto fail;
	}

	do fputs(ptr, fp); while ((ptr = fetch(sd, buf, len)));

	shutdown(sd, SHUT_RDWR);
	close(sd);

	rewind(fp);
	return fp;
}

#ifndef LOCALSTATEDIR
static int usage(void)
{
	printf("Usage: uget [-d] URL\n");
	return 0;
}

int main(int argc, char *argv[])
{
	char *buf;
	FILE *fp;
	int opt = 1;

	if (argc < 2)
		return usage();

	while (argv[opt][0] == '-') {
		if (!strcmp(argv[opt], "-d")) {
			debug = 1;
			opt++;
		}
	}

	buf = calloc(1, BUFSIZ);
	if (!buf)
		err(1, "Failed allocating  (%d bytes) receive buffer", BUFSIZ);

	fp = uget(argv[opt], buf, BUFSIZ);
	if (!fp)
		return 1;

	while (fgets(buf, BUFSIZ, fp))
		fputs(buf, stdout);
	fclose(fp);

	return 0;
}
#endif
