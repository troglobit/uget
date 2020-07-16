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

#define dbg(fmt, args...) if (verbose > 1) printf(fmt "\n", ##args)
#define vrb(fmt, args...) if (verbose > 0) printf(fmt "\n", ##args)

struct uget {
	char     *cmd;		/* GET/HEAD/POST */
	char     *server;
	uint16_t  port;
	char     *location;

	char      host[20];

	int       redirect;
	char      redirect_url[256];
};

static int verbose;

static void vrbuf(char *buf, char *prefix)
{
	char *ptr = buf;

	if (!verbose || !ptr)
		return;

	while (*ptr) {
		fputs(prefix, stdout);
		while (*ptr && *ptr != '\r')
			putchar(*ptr++);

		if (!strncmp(ptr, "\r\n", 2)) {
			ptr += 2;
			puts("");
		} else
			break;
	}
}

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

	dbg("* Parsed URL: FROM %s PORT %d %s /%s", ctx->server, ctx->port, ctx->cmd, ctx->location);

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

static int request(int sd, struct uget *ctx)
{
	struct pollfd pfd;
	ssize_t num;
	size_t len;
	char buf[256];

	len = snprintf(buf, sizeof(buf), "%s /%s HTTP/1.1\r\n"
		       "Host: %s\r\n"
		       "User-Agent: " PACKAGE_NAME "/" PACAKGE_VERSION "\r\n"
		       "Accept: */*\r\n"
		       "\r\n",
		       ctx->cmd, ctx->location, ctx->server);
	vrbuf(buf, "> ");

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

static int hello(struct addrinfo *ai, struct uget *ctx)
{
	struct sockaddr_in *sin;
	struct addrinfo *rp;
	int sd;

	for (rp = ai; rp != NULL; rp = rp->ai_next) {
		struct timeval timeout = { 0, 200000 };

		sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sd == -1)
			continue;

		sin = (struct sockaddr_in *)rp->ai_addr;
		inet_ntop(rp->ai_family, &sin->sin_addr, ctx->host, sizeof(ctx->host));
		vrb("* Trying %s:%d ...", ctx->host, ntohs(sin->sin_port));

		/* Attempt to adjust recv timeout */
		if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
			warn("Failed setting recv() timeout");
		else
			vrb("* SO_RCVTIMEO %ld.%ld sec set", timeout.tv_sec, timeout.tv_usec / 1000);

		/* Attempt to connect to this address:port */
		if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* Success */

		warn("Failed connecting to %s:%d", ctx->host, ntohs(sin->sin_port));

		close(sd);
	}

	if (rp == NULL)
		return -1;

	vrb("* Connected to %s (%s) port %d", ctx->server, ctx->host, ntohs(sin->sin_port));

	return request(sd, ctx);
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

static void head(char *buf, struct uget *ctx)
{
	char *ptr;

	if (strcmp(ctx->cmd, "HEAD"))
		return;

	ptr = strchr(buf, ':');
	if (!ptr) {
		puts(buf);
		return;
	}

	*ptr = 0;
	printf("\e[1m%s:\e[0m%s\n", buf, &ptr[1]);
	*ptr = ':';
}

static char *parse_headers(char *buf, struct uget *ctx)
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
	content[2] = 0;
	content += 4;

	ptr = bufgets(buf);
	if (!ptr) {
		warnx("no HTTP response code");
		return NULL;
	}
	vrb("< %s", ptr);
	head(ptr, ctx);

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
	case 301:
		ctx->redirect = 1;
		content = NULL;
		break;
	default:
		warnx("invalid response: %d %s", code, mesg);
		content = NULL;
		break;
	}

	while ((ptr = bufgets(NULL))) {
		vrb("< %s", ptr);
		head(ptr, ctx);
		if (ctx->redirect && !strncasecmp("Location: ", ptr, 10))
			snprintf(ctx->redirect_url, sizeof(ctx->redirect_url), "%s", &ptr[10]);
	}

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

FILE *uget(char *cmd, char *url, char *buf, size_t len)
{
	struct uget ctx = { cmd };
	struct addrinfo *ai;
	FILE *fp;
	char *ptr;
	int sd;

	dbg("* URL: %s", url);
retry:
	if (split(url, &ctx))
		return NULL;

	if (nslookup(&ctx, &ai))
		return NULL;

	sd = hello(ai, &ctx);
	freeaddrinfo(ai);
	if (-1 == sd)
		return NULL;

	if (!fetch(sd, buf, len)) {
		warnx("no data");
	fail:
		shutdown(sd, SHUT_RDWR);
		close(sd);
		return NULL;
	}

	ptr = parse_headers(buf, &ctx);
	if (!ptr) {
		if (ctx.redirect) {
			dbg("* Redirecting to %s ...", ctx.redirect_url);
			url = ctx.redirect_url;
			goto retry;
		}
		goto fail;
	}

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
	printf("Usage: uget [-v] [-o FILE] URL\n");
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp, *out = stdout;
	char *buf, *fn = NULL;
	char *cmd = "GET";
	int opt = 1;
	int rc;

	if (argc < 2)
		return usage();

	while (argv[opt][0] == '-') {
		if (!strcmp(argv[opt], "-v")) {
			opt++;
			verbose++;
		} else if (!strcmp(argv[opt], "-o")) {
			opt++;
			fn = argv[opt++];
		} else if (!strcmp(argv[opt], "-I")) {
			opt++;
			cmd = "HEAD";
		}
	}

	if (fn) {
		out = fopen(fn, "w");
		if (!out)
			err(1, "Failed opening output file %s", fn);
		dbg("* Saving output to %s", fn);
	}

	buf = calloc(1, BUFSIZ);
	if (!buf)
		err(1, "Failed allocating  (%d bytes) receive buffer", BUFSIZ);

	fp = uget(cmd, argv[opt], buf, BUFSIZ);
	if (fp) {
		while (fgets(buf, BUFSIZ, fp))
			fputs(buf, out);
		fclose(fp);
		rc = 0;
	} else
		rc = 1;
	fclose(out);

	return rc;
}
#endif
