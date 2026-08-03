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
	if(conn == nil)
		return -1;

	conn->serverName = host;

	/* pushtls() na libc do 9front lida com o handshake TLS e retorna o novo fd seguro */
	tlsfd = pushtls(fd, host, nil, conn);
	free(conn);
	if(tlsfd < 0)
		werrstr("pushtls failed: %r");

	return tlsfd;
}

int
vpn_http_post(int fd, char *host, char *path, char *body, char *resp, int maxresp)
{
	char req[1024];
	int reqlen, n, total;

	reqlen = snprint(req, sizeof(req),
		"POST /%s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Accept: */*\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		path, host, (int)strlen(body), body);

	if(write(fd, req, reqlen) != reqlen){
		fprint(2, "vpnfs: http post write failed: %r\n");
		return -1;
	}

	total = 0;
	memset(resp, 0, maxresp);
	while(total < maxresp - 1){
		n = read(fd, resp + total, maxresp - 1 - total);
		if(n <= 0)
			break;
		total += n;
	}
	resp[total] = '\0';
	return total;
}

int
vpn_http_get_tunnel(int fd, char *host, char *cookie)
{
	char req[1024];
	int reqlen;

	reqlen = snprint(req, sizeof(req),
		"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Cookie: %s\r\n"
		"Connection: keep-alive\r\n"
		"\r\n",
		host, cookie);

	if(write(fd, req, reqlen) != reqlen){
		fprint(2, "vpnfs: sslvpn-tunnel request failed: %r\n");
		return -1;
	}
	return 0;
}

int
vpn_create_pipes(VpnSession *s)
{
	int p1[2], p2[2];

	if(pipe(p1) < 0 || pipe(p2) < 0){
		fprint(2, "vpnfs: pipe creation failed: %r\n");
		return -1;
	}

	s->pipe_in = p1[0];   /* Application reads from p1[0] */
	s->pipe_out = p2[1];  /* Application writes to p2[1] */
	return 0;
}
