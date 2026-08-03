#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "../vpnfs.h"

static const char clthello[] = "GFtype\0clthello\0SVPNCOOKIE";

typedef struct FortinetPriv FortinetPriv;
struct FortinetPriv {
	int auth_fd;
};

static char*
extract_cookie(char *resp, char *cookie_name)
{
	char *p, *end, *val;
	int name_len;

	name_len = strlen(cookie_name);
	p = strstr(resp, cookie_name);
	if(p == nil)
		return nil;

	p += name_len;
	if(*p == '=')
		p++;

	/* Find delimiter: ';', '\r', '\n', '&', '"', ' ', '\0' */
	end = p;
	while(*end && *end != ';' && *end != '\r' && *end != '\n' && *end != '&' && *end != '"' && *end != ' ')
		end++;

	val = malloc(end - p + 1);
	if(val == nil)
		return nil;

	memmove(val, p, end - p);
	val[end - p] = '\0';
	return val;
}

static char*
prompt_token(char *prompt, char *buf, int buflen)
{
	int fd, n;

	/* Força o envio da string para o stdout (fd 1) sem esperar \n */
	fprint(1, "%s", prompt);

	fd = open("/dev/cons", OREAD);
	if(fd < 0)
		return nil;

	memset(buf, 0, buflen);
	n = read(fd, buf, buflen - 1);
	close(fd);

	if(n <= 0)
		return nil;

	buf[n] = '\0';
	while(n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' ')){
		buf[n-1] = '\0';
		n--;
	}
	return buf;
}

static int
fortinet_init(VpnSession *s)
{
	FortinetPriv *priv;

	priv = mallocz(sizeof(FortinetPriv), 1);
	if(priv == nil){
		fprint(2, "vpnfs: fortinet_init memory allocation failed\n");
		return -1;
	}
	priv->auth_fd = -1;
	s->priv = priv;
	return 0;
}

static int
fortinet_auth(VpnSession *s)
{
	int raw_fd, tls_fd, n;
	char body[1024];
	char resp[4096];
	char req[512];
	char *cookie_val, *new_cookie;
	char *token_str;
	char token_buf[128];

	if(s->cfg->user == nil || s->cfg->pass == nil){
		fprint(2, "vpnfs: fortinet_auth missing username or password\n");
		return -1;
	}

	if(s->cfg->realm != nil && *s->cfg->realm != '\0')
		snprint(body, sizeof(body), "username=%s&credential=%s&realm=%s&ajax=1&just_logged_in=1",
			s->cfg->user, s->cfg->pass, s->cfg->realm);
	else
		snprint(body, sizeof(body), "username=%s&credential=%s&ajax=1&just_logged_in=1",
			s->cfg->user, s->cfg->pass);

	if(s->cfg->verbose)
		print("vpnfs: connecting to %s:%s for authentication...\n", s->cfg->host, s->cfg->port);

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0) return -1;
	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0) return -1;

	if(s->cfg->verbose)
		print("vpnfs: sending login request to /remote/logincheck...\n");

	n = vpn_http_post(tls_fd, s->cfg->host, "remote/logincheck", body, resp, sizeof(resp));
	close(tls_fd);

	if(n <= 0){
		fprint(2, "vpnfs: fortinet_auth failed to receive HTTP response\n");
		return -1;
	}

	cookie_val = extract_cookie(resp, "SVPNCOOKIE");

	/* Trata Desafio 2FA (FortiToken) */
	if(cookie_val == nil || strstr(resp, "tokeninfo=") != nil || strstr(resp, "2fa") != nil){
		char *magic_val = extract_cookie(resp, "magic");
		char *reqid_val = extract_cookie(resp, "reqid");
		char *polid_val = extract_cookie(resp, "polid");

		if(cookie_val != nil){ free(cookie_val); cookie_val = nil; }

		if(s->cfg->verbose)
			print("vpnfs: 2FA challenge detected\n");

		if(s->cfg->token != nil && *s->cfg->token != '\0'){
			token_str = s->cfg->token;
		}else{
			if(prompt_token("FortiToken Code: ", token_buf, sizeof(token_buf)) == nil){
				free(magic_val); free(reqid_val); free(polid_val);
				fprint(2, "vpnfs: failed to read token code from console\n");
				return -1;
			}
			token_str = token_buf;
		}

		snprint(body, sizeof(body),
			"username=%s&credential=%s&code=%s&magic=%s&reqid=%s&polid=%s&ajax=1",
			s->cfg->user, s->cfg->pass, token_str,
			magic_val ? magic_val : "",
			reqid_val ? reqid_val : "",
			polid_val ? polid_val : "");

		free(magic_val); free(reqid_val); free(polid_val);

		if(s->cfg->verbose)
			print("vpnfs: sending 2FA token verification to /remote/logincheck...\n");

		raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
		if(raw_fd < 0) return -1;
		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd < 0) return -1;

		n = vpn_http_post(tls_fd, s->cfg->host, "remote/logincheck", body, resp, sizeof(resp));
		close(tls_fd);

		if(n <= 0) return -1;
		cookie_val = extract_cookie(resp, "SVPNCOOKIE");
	}

	if(cookie_val == nil){
		fprint(2, "vpnfs: SVPNCOOKIE not found in login response\n");
		return -1;
	}

	snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", cookie_val);
	free(cookie_val);

	if(s->cfg->verbose)
		print("vpnfs: authenticated successfully (got SVPNCOOKIE)\n");

	/* ALOCAÇÃO DE VPN E ATUALIZAÇÃO DO COOKIE (/remote/index & /remote/fortisslvpn) */
	if(s->cfg->verbose)
		print("vpnfs: requesting VPN session allocation...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd >= 0){
		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd >= 0){
			snprint(req, sizeof(req),
				"GET /remote/index HTTP/1.1\r\n"
				"Host: %s:%s\r\n"
				"User-Agent: Mozilla/5.0 SV1\r\n"
				"Cookie: %s\r\n"
				"Connection: close\r\n\r\n",
				s->cfg->host, s->cfg->port, s->cookie);
			write(tls_fd, req, strlen(req));
			memset(resp, 0, sizeof(resp));
			read(tls_fd, resp, sizeof(resp) - 1);
			close(tls_fd);

			new_cookie = extract_cookie(resp, "SVPNCOOKIE");
			if(new_cookie != nil){
				snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", new_cookie);
				free(new_cookie);
			}
		}
	}

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd >= 0){
		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd >= 0){
			snprint(req, sizeof(req),
				"GET /remote/fortisslvpn HTTP/1.1\r\n"
				"Host: %s:%s\r\n"
				"User-Agent: Mozilla/5.0 SV1\r\n"
				"Cookie: %s\r\n"
				"Connection: close\r\n\r\n",
				s->cfg->host, s->cfg->port, s->cookie);
			write(tls_fd, req, strlen(req));
			memset(resp, 0, sizeof(resp));
			read(tls_fd, resp, sizeof(resp) - 1);
			close(tls_fd);

			new_cookie = extract_cookie(resp, "SVPNCOOKIE");
			if(new_cookie != nil){
				snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", new_cookie);
				free(new_cookie);
			}
		}
	}

	return 0;
}

static int
fortinet_connect_tunnel(VpnSession *s)
{
	char addr[256];
	uchar pkt[1024];
	uchar resp[1024];
	int udp_fd, pkt_len, cookie_len, n;
	char *cookie_val;

	if(s->cookie[0] == '\0'){
		fprint(2, "vpnfs: no session cookie available for tunnel connection\n");
		return -1;
	}

	/* Extrai apenas o valor do SVPNCOOKIE (remove o prefixo SVPNCOOKIE= se existir) */
	cookie_val = strchr(s->cookie, '=');
	if(cookie_val != nil)
		cookie_val++;
	else
		cookie_val = s->cookie;

	if(s->cfg->verbose)
		print("vpnfs: establishing UDP tunnel to %s:%s...\n", s->cfg->host, s->cfg->port);

	/* Dial UDP nativo do Plan 9 */
	snprint(addr, sizeof(addr), "udp!%s!%s", s->cfg->host, s->cfg->port);
	udp_fd = dial(addr, nil, nil, nil);
	if(udp_fd < 0){
		fprint(2, "vpnfs: dial UDP %s failed: %r\n", addr);
		return -1;
	}

	/* Monta o pacote clthello:
	 * Headers: "GFtype\0clthello\0SVPNCOOKIE\0" + cookie_val + "\0"
	 */
	cookie_len = strlen(cookie_val);

	/* Offset do payload apos os 2 bytes de tamanho */
	pkt_len = 2;
	memmove(pkt + pkt_len, clthello, sizeof(clthello));
	pkt_len += sizeof(clthello);
	memmove(pkt + pkt_len, cookie_val, cookie_len + 1);
	pkt_len += cookie_len + 1;

	/* Insere o tamanho total do payload nos primeiros 2 bytes (Big Endian) */
	pkt[0] = ((pkt_len - 2) >> 8) & 0xFF;
	pkt[1] = (pkt_len - 2) & 0xFF;

	if(s->cfg->verbose)
		print("vpnfs: sending UDP clthello handshake (%d bytes)...\n", pkt_len);

	if(write(udp_fd, pkt, pkt_len) != pkt_len){
		fprint(2, "vpnfs: write clthello to UDP socket failed: %r\n");
		close(udp_fd);
		return -1;
	}

	/* Recebe o svrhello do servidor */
	memset(resp, 0, sizeof(resp));
	n = read(udp_fd, resp, sizeof(resp) - 1);
	if(n <= 0){
		fprint(2, "vpnfs: no response received for UDP clthello: %r\n");
		close(udp_fd);
		return -1;
	}

	if(s->cfg->verbose){
		int i;
		print("vpnfs: received UDP svrhello response (%d bytes):\n", n);
		for(i = 0; i < (n < 64 ? n : 64); i++)
			print(" %02x", resp[i]);
		print("\n");
	}

	s->tls_fd = udp_fd; /* Armazena o socket UDP ativo */
	return 0;
}

static int
fortinet_read_packet(VpnSession *s, uchar *buf, int maxlen)
{
	int n;

	n = read(s->tls_fd, buf, maxlen);
	if(n <= 0)
		return -1;

	if(s->cfg->verbose)
		print("vpnfs: rx UDP packet len=%d\n", n);

	return n;
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	if(write(s->tls_fd, buf, len) != len){
		fprint(2, "vpnfs: write UDP packet failed: %r\n");
		return -1;
	}
	return len;
}

static void
fortinet_close(VpnSession *s)
{
	FortinetPriv *priv;

	if(s->tls_fd >= 0){
		close(s->tls_fd);
		s->tls_fd = -1;
	}

	if(s->priv != nil){
		priv = s->priv;
		free(priv);
		s->priv = nil;
	}
}

VpnDriver fortinet_driver = {
	"fortinet",
	fortinet_init,
	fortinet_auth,
	fortinet_connect_tunnel,
	fortinet_read_packet,
	fortinet_write_packet,
	fortinet_close,
};
