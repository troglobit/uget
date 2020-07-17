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

int verbose;

static void head(char *buf, struct conn *c);


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

static int split(char *url, struct conn *c)
{
	char *ptr, *pptr;

	if (!url)
		return 1;

	/* Figure out protocol to use */
	if (!strncmp(url, "http://", 7))
		c->do_ssl = 0;
	else if (!strncmp(url, "https://", 8))
		c->do_ssl = 1;
	else
		return 1;

	ptr = strstr(url, "://");
	if (!ptr)
		ptr = url;
	else
		ptr += 3;

	/* Allow standard http://[IP:V6:ADDR]:PORT syntax */
	if (*ptr == '[') {
		ptr++;
		c->server = ptr;
		ptr = strchr(ptr, ']');
		if (!ptr) {
			errno = EINVAL;
			return 1;
		}
		*ptr++ = 0;
	} else
		c->server = ptr;

	ptr = strchr(ptr, ':');
	if (ptr) {
		*ptr++ = 0;
		pptr = ptr;
	} else {
		if (c->do_ssl)
			pptr = "443";
		else
			pptr = "80";

		/* continue parsing here */
		ptr = c->server;
	}

	ptr = strchr(ptr, '/');
	if (!ptr)
		ptr = "";
	else
		*ptr++ = 0;
	c->location = ptr;

	if (pptr)
		c->port = atoi(pptr);

	if (!c->server)
		return 1;

	dbg("* Parsed URL: FROM %s PORT %d %s /%s", c->server, c->port, c->cmd, c->location);

	return 0;
}

static int nslookup(struct conn *c, struct addrinfo **result)
{
	struct addrinfo hints;
	char service[10];
	int rc;

	snprintf(service, sizeof(service), "%d", c->port);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags    = 0;
	hints.ai_protocol = 0;

	rc = getaddrinfo(c->server, service, &hints, result);
	if (rc) {
		warnx("Failed looking up %s:%s: %s", c->server, service, gai_strerror(rc));
		return -1;
	}

	return 0;
}

static char *uget_recv(struct conn *c, char *buf, size_t len)
{
	struct pollfd pfd;
	ssize_t num;

	pfd.fd = c->sd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) < 0) {
		warn("Server %s: %s", c->host, strerror(errno));
		return NULL;
	}

	if (c->do_ssl)
		return ssl_recv(c, buf, len);

	while ((num = recv(c->sd, buf, len - 1, 0)) < 0) {
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN)
			warn("no data");
		return NULL;
	}
	buf[num] = 0;
	c->len = num;

	return buf;
}

static int uget_send(struct conn *c, char *buf, size_t len)
{
	ssize_t num;

	if (c->do_ssl)
		return ssl_send(c, buf, len);

	while ((num = send(c->sd, buf, len, 0)) < 0) {
		if (errno == EINTR)
			continue;
		break;
	}

	return num;
}

static int request(struct conn *c)
{
	ssize_t num;
	size_t len;

	len = snprintf(c->buf, c->len, "%s /%s HTTP/1.1\r\n"
		       "Host: %s\r\n"
		       "User-Agent: %s/%s\r\n"
		       "Accept: */*\r\n"
		       "\r\n",
		       c->cmd, c->location, c->server,
		       PACKAGE_NAME, PACKAGE_VERSION);
	vrbuf(c->buf, "> ");

	num = uget_send(c, c->buf, len);
	if (num < 0) {
		warn("Failed sending HTTP GET /%s to %s:%d", c->location, c->host, c->port);
		close(c->sd);
		return -1;
	}

	return 0;
}

static short getaddrinfo_port(struct addrinfo *ai)
{
    if (ai->ai_family == AF_INET)
        return (((struct sockaddr_in*)ai->ai_addr)->sin_port);

    return (((struct sockaddr_in6*)ai->ai_addr)->sin6_port);
}

static int hello(struct addrinfo *ai, struct conn *c)
{
	struct addrinfo *rp;
	short port;
	int sd;

	for (rp = ai; rp != NULL; rp = rp->ai_next) {
		struct timeval timeout = { 0, 200000 };
		socklen_t len;
		int val = 1;

		sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sd == -1)
			continue;

		if (getnameinfo(rp->ai_addr, rp->ai_addrlen, c->host, sizeof(c->host), NULL, 0, NI_NUMERICHOST))
			continue;
		port = getaddrinfo_port(rp);
		vrb("* Trying %s:%d ...", c->host, ntohs(port));

		if (setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
			warn("* Failed %s TCP_NODELAY", val ? "setting" : "clearing");

		len = sizeof(val);
		if (!getsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &val, &len))
			vrb("* TCP_NODELAY %s", val ? "set" : "not set");

		/* Attempt to adjust socket timeout */
		if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
			warn("* Failed setting recv() timeout");
		else
			vrb("* SO_RCVTIMEO %ld.%ld sec set", timeout.tv_sec, timeout.tv_usec / 1000);
		if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
			warn("* Failed setting send() timeout");
		else
			vrb("* SO_SNDTIMEO %ld.%ld sec set", timeout.tv_sec, timeout.tv_usec / 1000);

		/* Attempt to connect to this address:port */
		if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* Success */

		warn("Failed connecting to %s:%d", c->host, ntohs(port));

		close(sd);
	}

	if (rp == NULL)
		return -1;

	vrb("* Connected to %s (%s) port %d", c->server, c->host, ntohs(port));
	c->sd = sd;
	if (c->do_ssl && ssl_open(c)) {
		warn("Failed opening HTTPS connection to %s", c->server);
		close(sd);
		return -1;
	}

	return request(c);
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

static char *parse_headers(struct conn *c)
{
	char version[8];
	char mesg[32];
	char *content;
	char *ptr, *p;
	int code = 0;

	/* Find start of content */
	content = strstr(c->buf, "\r\n\r\n");
	if (!content) {
		warnx("max header size");
		return NULL;
	}
	content[2] = 0;
	content += 4;
	c->len  -= content - c->buf;

	ptr = bufgets(c->buf);
	if (!ptr) {
		warnx("no HTTP response code");
		return NULL;
	}
	vrb("< %s", ptr);
	head(ptr, c);

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
		c->redirect = 1;
		content = NULL;
		break;
	default:
		warnx("invalid response: %d %s", code, mesg);
		content = NULL;
		break;
	}

	while ((ptr = bufgets(NULL))) {
		vrb("< %s", ptr);
		head(ptr, c);
		if (c->redirect && !strncasecmp("Location: ", ptr, 10))
			snprintf(c->redirect_url, sizeof(c->redirect_url), "%s", &ptr[10]);
		else if (!strncasecmp("Content-Length: ", ptr, 16))
			c->content_len = atoi(&ptr[16]);
	}

	return content;
}

FILE *uget(char *cmd, int strict, char *url, char *buf, size_t len)
{
	struct conn c = { 0 };
	struct addrinfo *ai;
	FILE *fp;
	char *ptr;

retry:
	/* Let HTTP request reuse buf */
	c.cmd = cmd;
	c.buf = buf;
	c.len = len;
	c.strict = strict;

	dbg("* URL: %s", url);
	if (split(url, &c))
		return NULL;

	if (nslookup(&c, &ai))
		return NULL;

	ssl_init(&c);
	if (hello(ai, &c)) {
	err:	freeaddrinfo(ai);
		ssl_exit(&c);
		return NULL;
	}

	if (!uget_recv(&c, buf, len)) {
	fail:
		if (c.do_ssl)
			ssl_close(&c);
		close(c.sd);
		goto err;
	}

	ptr = parse_headers(&c);
	if (!ptr) {
		if (c.redirect) {
			dbg("* Redirecting to %s ...", c.redirect_url);
			url = c.redirect_url;
			goto retry;
		}
		goto fail;
	}

	fp = tmpfile();
	if (!fp) {
		warnx("failed creating tempfile");
		goto fail;
	}

	if (strcmp(c.cmd, "HEAD")) {
		do {
			fputs(ptr, fp);
			c.content_len -= c.len;
			if (c.content_len > 0)
				ptr = uget_recv(&c, buf, len);
		} while (c.content_len > 0);
		rewind(fp);
	}

	freeaddrinfo(ai);
	if (c.do_ssl)
		ssl_close(&c);
	shutdown(c.sd, SHUT_RDWR);
	close(c.sd);
	ssl_exit(&c);

	return fp;
}

#ifndef STANDALONE
static void head(char *buf, struct conn *c)
{
	(void)buf;
	(void)c;
	return;
}

#else  /* STANDALONE */
#include <getopt.h>

static void head(char *buf, struct conn *c)
{
	char *ptr;

	if (strcmp(c->cmd, "HEAD"))
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

static int usage(void)
{
	printf("Usage: uget [-svI] [-o FILE] URL\n");
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp, *out = stdout;
	char *buf, *fn = NULL;
	char *cmd = "GET";
	int strict = 1;
	int rc, c;

	while ((c = getopt(argc, argv, "Io:sv")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'o':
			fn = optarg;
			break;
		case 's':
			strict = 0;
			break;
		case 'I':
			cmd = "HEAD";
			break;
		default:
			return usage();
		}
	}

	if (argc <= optind)
		return usage();

	if (fn) {
		out = fopen(fn, "w");
		if (!out)
			err(1, "Failed opening output file %s", fn);
		dbg("* Saving output to %s", fn);
	}

	buf = calloc(1, BUFSIZ);
	if (!buf)
		err(1, "Failed allocating  (%d bytes) receive buffer", BUFSIZ);

	fp = uget(cmd, strict, argv[optind], buf, BUFSIZ);
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
#endif /* STANDALONE */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
