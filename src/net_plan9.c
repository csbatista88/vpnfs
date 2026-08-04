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
	int reqlen, n, total, content_len, header_len;
	char *hdr_end, *cl;

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
	content_len = -1;
	header_len = -1;
	memset(resp, 0, maxresp);

	while(total < maxresp - 1){
		n = read(fd, resp + total, maxresp - 1 - total);
		if(n <= 0)
			break;
		total += n;
		resp[total] = '\0';

		if(header_len < 0){
			hdr_end = strstr(resp, "\r\n\r\n");
			if(hdr_end != nil){
				header_len = (hdr_end - resp) + 4;
				cl = cistrstr(resp, "content-length:");
				if(cl != nil && cl < hdr_end){
					cl += 15;
					while(*cl == ' ' || *cl == '\t')
						cl++;
					content_len = atoi(cl);
				}
			}
		}

		if(header_len >= 0 && content_len >= 0){
			if(total >= header_len + content_len)
				break;
		}
	}
	resp[total] = '\0';
	return total;
}

int
vpn_http_get_tunnel(int fd, char *host, char *port, char *cookie)
{
	char req[1024];
	int reqlen;

	USED(port);

	reqlen = snprint(req, sizeof(req),
		"GET /remote/sslvpn-tunnel HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Cookie: %s\r\n"
		"Connection: keep-alive\r\n"
		"\r\n",
		host, cookie);

	if(write(fd, req, reqlen) != reqlen){
		fprint(2, "vpnfs: sslvpn-tunnel write failed: %r\n");
		return -1;
	}

	return 0;
}

static int
vpn_post_srv(char *name, int fd)
{
	char path[64];
	int sfd;

	snprint(path, sizeof(path), "/srv/%s", name);
	sfd = create(path, OWRITE, 0666);
	if(sfd < 0)
		return -1;
	if(fprint(sfd, "%d", fd) < 0){
		close(sfd);
		return -1;
	}
	close(sfd);
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

	s->pipe_in = p1[0];    /* Main process reads packets to send over tunnel */
	s->srv_in_fd = p1[1];  /* Reference descriptor for /srv/vpnfs.in writer */

	s->pipe_out = p2[1];   /* Main process writes packets received from tunnel */
	s->srv_out_fd = p2[0]; /* Reference descriptor for /srv/vpnfs.out reader */

	vpn_post_srv("vpnfs.in", p1[1]);
	vpn_post_srv("vpnfs.out", p2[0]);
	vpn_post_srv("vpnfs", p2[0]);

	return 0;
}
