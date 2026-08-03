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

	/* tlsClient lida com o handshake SSL/TLS completo e retorna o novo fd seguro */
	tlsfd = tlsClient(fd, conn);
	
	/* A struct TLSconn e seus campos alocados podem ser liberados após o handshake */
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

int
vpn_http_post(int fd, char *host, char *path, char *body, char *resp, int maxresp)
{
	char req[1024];
	char formatted_path[256];
	int reqlen, n, total;

	if(path[0] == '/')
		snprint(formatted_path, sizeof(formatted_path), "%s", path);
	else
		snprint(formatted_path, sizeof(formatted_path), "/%s", path);

	reqlen = snprint(req, sizeof(req),
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Accept: */*\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		formatted_path, host, (int)strlen(body), body);

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
vpn_http_get_tunnel(int fd, char *host, char *port, char *cookie)
{
	char req[1024];
	char c;
	int reqlen, state;

	if(port != nil && *port != '\0' && strcmp(port, "443") != 0)
		reqlen = snprint(req, sizeof(req),
			"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
			"Host: %s:%s\r\n"
			"User-Agent: Mozilla/5.0 SV1\r\n"
			"Cookie: %s\r\n"
			"Accept: */*\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			host, port, cookie);
	else
		reqlen = snprint(req, sizeof(req),
			"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: Mozilla/5.0 SV1\r\n"
			"Cookie: %s\r\n"
			"Accept: */*\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			host, cookie);

	if(write(fd, req, reqlen) != reqlen){
		fprint(2, "vpnfs: sslvpn-tunnel request failed: %r\n");
		return -1;
	}

	/* Consome a resposta HTTP ("HTTP/1.1 200 OK ... \r\n\r\n") byte a byte */
	state = 0;
	while(read(fd, &c, 1) == 1){
		switch(state){
		case 0: if(c == '\r') state = 1; else if(c == '\n') state = 2; break;
		case 1: if(c == '\n') state = 2; else if(c == '\r') state = 1; else state = 0; break;
		case 2: if(c == '\r') state = 3; else state = 0; break;
		case 3: if(c == '\n') return 0; /* Cabeçalho HTTP limpo, socket pronto no stream binario */
			else if(c == '\r') state = 1; else state = 0; break;
		}
	}

	fprint(2, "vpnfs: unexpected EOF reading tunnel response\n");
	return -1;
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
