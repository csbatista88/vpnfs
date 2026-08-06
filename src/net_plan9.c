#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "vpnfs.h"

int
vpn_dial(char *host, char *port)
{
	char *addr;
	int fd;

	if(port == nil || *port == '\0')
		port = "443";

	addr = netmkaddr(host, "tcp", port);
	fd = dial(addr, nil, nil, nil);
	if(fd < 0){
		fprint(2, "vpnfs: dial %s failed: %r\n", addr);
		return -1;
	}
	return fd;
}

int
vpn_pushtls(int fd, char *host)
{
	TLSconn *conn;
	int tlsfd;

	conn = (TLSconn*)mallocz(sizeof(TLSconn), 1);
	if(conn == nil){
		werrstr("out of memory");
		return -1;
	}

	conn->serverName = host;

	tlsfd = tlsClient(fd, conn);

	if(conn->cert != nil)
		free(conn->cert);
	if(conn->sessionID != nil)
		free(conn->sessionID);
	free(conn);

	if(tlsfd < 0){
		werrstr("tlsClient handshake failed: %r");
		return -1;
	}

	return tlsfd;
}

static void
hostport(char *host, char *port, char *buf, int len)
{
	if(port == nil || port[0] == '\0' || cistrcmp(port, "443") == 0)
		snprint(buf, len, "%s", host);
	else
		snprint(buf, len, "%s:%s", host, port);
}

int
vpn_http_status(char *resp)
{
	char *p;

	if(resp == nil)
		return -1;

	if(strncmp(resp, "HTTP/", 5) != 0)
		return -1;

	p = strchr(resp, ' ');
	if(p == nil)
		return -1;

	while(*p == ' ')
		p++;

	return atoi(p);
}

char*
vpn_urlencode(char *s)
{
	char *r, *p;
	uchar c;

	if(s == nil)
		return strdup("");

	r = malloc(strlen(s)*3 + 1);
	if(r == nil)
		return nil;

	p = r;
	while(*s){
		c = *(uchar*)s++;
		if((c >= 'A' && c <= 'Z') ||
		   (c >= 'a' && c <= 'z') ||
		   (c >= '0' && c <= '9') ||
		   c == '-' || c == '_' || c == '.' || c == '~'){
			*p++ = c;
		}else{
			snprint(p, 4, "%%%02x", c);
			p += 3;
		}
	}
	*p = '\0';
	return r;
}

/*
 * Generic HTTP request helper.
 * Uses Connection: close and reads the whole response.
 */
int
vpn_http_request(int fd, char *host, char *port, char *method,
                 char *path, char *ctype, char *body, char *cookie,
                 char *resp, int maxresp)
{
	char req[2048], hp[256];
	char *hdr_end, *p, *chunk;
	int n, total, clen, hlen, content_len, chunked;

	hostport(host, port, hp, sizeof(hp));

	clen = body ? strlen(body) : 0;

	n = snprint(req, sizeof(req),
		"%s %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Accept: */*\r\n"
		"Accept-Encoding: identity\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-store, no-cache, must-revalidate\r\n"
		"If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n",
		method, path, hp);

	if(cookie != nil && cookie[0] != '\0')
		n += snprint(req+n, sizeof(req)-n, "Cookie: %s\r\n", cookie);

	if(ctype != nil)
		n += snprint(req+n, sizeof(req)-n, "Content-Type: %s\r\n", ctype);

	if(cistrcmp(method, "POST") == 0){
		n += snprint(req+n, sizeof(req)-n,
			"Origin: https://%s\r\n"
			"Referer: https://%s/remote/login\r\n"
			"X-Requested-With: XMLHttpRequest\r\n",
			hp, hp);
	}

	n += snprint(req+n, sizeof(req)-n,
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n",
		clen);

	if(write(fd, req, n) != n){
		fprint(2, "vpnfs: http request write failed: %r\n");
		return -1;
	}

	if(clen > 0 && write(fd, body, clen) != clen){
		fprint(2, "vpnfs: http body write failed: %r\n");
		return -1;
	}

	total = 0;
	memset(resp, 0, maxresp);

	while(total < maxresp-1){
		n = read(fd, resp + total, maxresp - 1 - total);
		if(n <= 0)
			break;
		total += n;
		resp[total] = '\0';

		hdr_end = strstr(resp, "\r\n\r\n");
		if(hdr_end == nil)
			continue;

		hlen = (hdr_end - resp) + 4;
		content_len = -1;
		chunked = 0;

		p = cistrstr(resp, "content-length:");
		if(p != nil && p < hdr_end)
			content_len = atoi(p + 15);

		p = cistrstr(resp, "transfer-encoding:");
		if(p != nil && p < hdr_end){
			chunk = cistrstr(p, "chunked");
			if(chunk != nil && chunk < hdr_end)
				chunked = 1;
		}

		if(!chunked && content_len >= 0){
			if(total >= hlen + content_len)
				break;
		}else if(chunked){
			if(strstr(hdr_end, "\r\n0\r\n\r\n") != nil)
				break;
		}
	}

	resp[total] = '\0';
	return total;
}

/*
 * Backward-compatible wrapper for POST requests.
 */
int
vpn_http_post(int fd, char *host, char *path, char *body, char *resp, int maxresp)
{
	return vpn_http_request(fd, host, nil, "POST", path, "application/x-www-form-urlencoded", body, nil, resp, maxresp);
}

/*
 * This request upgrades the TLS connection to the Fortinet PPP tunnel.
 * If successful, no normal HTTP response is received; PPP framing starts.
 */
int
vpn_http_get_tunnel(int fd, char *host, char *port, char *cookie)
{
	char req[2048], hp[256];
	int n;

	hostport(host, port, hp, sizeof(hp));

	n = snprint(req, sizeof(req),
		"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Accept: */*\r\n"
		"Accept-Encoding: identity\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-store, no-cache, must-revalidate\r\n"
		"If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n"
		"Content-Length: 0\r\n",
		hp);

	if(cookie != nil && cookie[0] != '\0')
		n += snprint(req+n, sizeof(req)-n, "Cookie: %s\r\n", cookie);

	n += snprint(req+n, sizeof(req)-n,
		"Connection: keep-alive\r\n"
		"\r\n");

	if(write(fd, req, n) != n){
		fprint(2, "vpnfs: sslvpn-tunnel write failed: %r\n");
		return -1;
	}

	return 0;
}

int
vpn_create_pipes(VpnSession *s)
{
	int p_to_ppp[2], p_from_ppp[2];

	if(pipe(p_to_ppp) < 0 || pipe(p_from_ppp) < 0){
		fprint(2, "vpnfs: pipe creation failed: %r\n");
		return -1;
	}

	/* TLS -> ip/ppp STDIN (0):
	 * vpnfs writes incoming TLS packets to s->pipe_out (p_to_ppp[1]),
	 * ip/ppp reads STDIN (0) from p_to_ppp[0].
	 */
	s->pipe_out = p_to_ppp[1];
	s->srv_out_fd = p_to_ppp[0];

	/* ip/ppp STDOUT (1) -> TLS:
	 * ip/ppp writes outgoing network packets to STDOUT (1) (p_from_ppp[1]),
	 * vpnfs reads from s->pipe_in (p_from_ppp[0]) to send over TLS.
	 */
	s->pipe_in = p_from_ppp[0];
	s->srv_in_fd = p_from_ppp[1];

	snprint(s->ttyname, sizeof(s->ttyname), "stdio");

	return 0;
}
