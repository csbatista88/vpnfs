#include <u.h>
#include <libc.h>
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
	int tlsfd, ctlfd;
	char buf[128];
	char dname[64];
	int n;

	USED(host);

	/* Try native libc pushtls first if available, or manual /net/tls/clone */
	ctlfd = open("/net/tls/clone", ORDWR|OCEXEC);
	if(ctlfd < 0){
		/* Fall back or report error */
		fprint(2, "vpnfs: opening /net/tls/clone failed: %r\n");
		return -1;
	}

	n = read(ctlfd, buf, sizeof(buf)-1);
	if(n <= 0){
		close(ctlfd);
		fprint(2, "vpnfs: reading /net/tls/clone failed: %r\n");
		return -1;
	}
	buf[n] = '\0';

	/* Pass existing socket to TLS stack */
	if(fprint(ctlfd, "fd %d", fd) < 0){
		close(ctlfd);
		fprint(2, "vpnfs: tls ctl fd setup failed: %r\n");
		return -1;
	}

	snprint(dname, sizeof(dname), "/net/tls/%s/data", buf);
	tlsfd = open(dname, ORDWR);
	close(ctlfd);

	if(tlsfd < 0){
		fprint(2, "vpnfs: open %s failed: %r\n", dname);
		return -1;
	}

	/* Plain socket fd is superseded by tlsfd */
	close(fd);
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
