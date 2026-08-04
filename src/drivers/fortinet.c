#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "../vpnfs.h"

typedef struct FortinetPriv FortinetPriv;
struct FortinetPriv {
	char ip[64];
	char dns1[64];
	char dns2[64];
};

static char*
extract_cookie(char *resp, char *cookie_name)
{
	char *p, *end, *val;
	int name_len;

	name_len = strlen(cookie_name);
	p = strstr(resp, cookie_name);
	if(p == nil) return nil;

	p += name_len;
	if(*p == '=') p++;

	end = p;
	while(*end && *end != ';' && *end != '\r' && *end != '\n' && *end != '&' && *end != '"' && *end != ' ')
		end++;

	val = malloc(end - p + 1);
	if(val == nil) return nil;

	memmove(val, p, end - p);
	val[end - p] = '\0';
	return val;
}

static char*
extract_xml_tag(char *xml, char *tag, char *attr)
{
	char search[128];
	char *p, *end, *val;

	USED(tag);
	snprint(search, sizeof(search), "%s=", attr);
	p = strstr(xml, search);
	if(p == nil) return nil;

	p += strlen(search);
	if(*p == '\'' || *p == '"') p++;

	end = p;
	while(*end && *end != '\'' && *end != '"' && *end != ' ' && *end != '>')
		end++;

	val = malloc(end - p + 1);
	if(val == nil) return nil;

	memmove(val, p, end - p);
	val[end - p] = '\0';
	return val;
}

static char*
prompt_token(char *prompt, char *buf, int buflen)
{
	int fd, n;

	fprint(1, "%s", prompt);
	fd = open("/dev/cons", OREAD);
	if(fd < 0) return nil;

	memset(buf, 0, buflen);
	n = read(fd, buf, buflen - 1);
	close(fd);

	if(n <= 0) return nil;

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
	if(priv == nil) return -1;
	s->priv = priv;
	return 0;
}

static int
fortinet_fetch_config(VpnSession *s)
{
	char req[512];
	char resp[4096];
	char *ip, *dns1, *hdr_end, *cl;
	int raw_fd, tls_fd, n, total, content_len, header_len;
	FortinetPriv *priv = s->priv;

	if(s->cookie[0] == '\0')
		return -1;

	if(s->cfg->verbose)
		print("vpnfs: fetching XML configuration via dedicated TLS connection...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0) return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0) return -1;

	snprint(req, sizeof(req),
		"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Cookie: %s\r\n"
		"Connection: close\r\n\r\n",
		s->cfg->host, s->cookie);

	if(write(tls_fd, req, strlen(req)) != strlen(req)){
		close(tls_fd);
		return -1;
	}

	memset(resp, 0, sizeof(resp));
	total = 0;
	content_len = -1;
	header_len = -1;

	while(total < sizeof(resp) - 1){
		n = read(tls_fd, resp + total, sizeof(resp) - 1 - total);
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
	close(tls_fd);

	if(s->cfg->verbose){
		print("vpnfs: XML config response (%d bytes):\n%s\n", total, resp);
	}

	ip = extract_xml_tag(resp, "assigned-addr", "ipv4");
	dns1 = extract_xml_tag(resp, "dns", "ip");

	if(ip != nil){
		snprint(priv->ip, sizeof(priv->ip), "%s", ip);
		if(s->cfg->verbose) print("vpnfs: assigned virtual IP: %s\n", ip);
		free(ip);
	}

	if(dns1 != nil){
		snprint(priv->dns1, sizeof(priv->dns1), "%s", dns1);
		if(s->cfg->verbose) print("vpnfs: assigned DNS server: %s\n", dns1);
		free(dns1);
	}

	return 0;
}

static int
fortinet_auth(VpnSession *s)
{
	int raw_fd, tls_fd, n;
	char body[1024];
	char resp[4096];
	char *cookie_val;
	char *token_str;
	char token_buf[128];

	if(s->cfg->user == nil || s->cfg->pass == nil) return -1;

	snprint(body, sizeof(body), "username=%s&credential=%s&ajax=1&just_logged_in=1",
		s->cfg->user, s->cfg->pass);

	if(s->cfg->verbose)
		print("vpnfs: connecting to %s:%s for authentication...\n", s->cfg->host, s->cfg->port);

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0) return -1;
	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0) return -1;

	n = vpn_http_post(tls_fd, s->cfg->host, "remote/logincheck", body, resp, sizeof(resp));
	close(tls_fd);

	if(n <= 0) return -1;

	cookie_val = extract_cookie(resp, "SVPNCOOKIE");

	if(cookie_val == nil || strstr(resp, "tokeninfo=") != nil || strstr(resp, "2fa") != nil){
		char *magic_val = extract_cookie(resp, "magic");
		char *reqid_val = extract_cookie(resp, "reqid");
		char *polid_val = extract_cookie(resp, "polid");

		if(cookie_val != nil){ free(cookie_val); cookie_val = nil; }

		if(s->cfg->token != nil && *s->cfg->token != '\0'){
			token_str = s->cfg->token;
		}else{
			if(prompt_token("FortiToken Code: ", token_buf, sizeof(token_buf)) == nil){
				free(magic_val); free(reqid_val); free(polid_val);
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
		fprint(2, "vpnfs: SVPNCOOKIE not found\n");
		return -1;
	}

	snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", cookie_val);
	free(cookie_val);

	if(s->cfg->verbose)
		print("vpnfs: authenticated successfully (got SVPNCOOKIE)\n");

	/* Busca o XML de configuracao em conexao TLS curta dedicada */
	fortinet_fetch_config(s);

	return 0;
}

static int
fortinet_connect_tunnel(VpnSession *s)
{
	int raw_fd, tls_fd;

	if(s->cookie[0] == '\0'){
		fprint(2, "vpnfs: no session cookie available for tunnel connection\n");
		return -1;
	}

	if(s->cfg->verbose)
		print("vpnfs: opening dedicated TLS connection for tunnel upgrade...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0)
		return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0)
		return -1;

	if(vpn_http_get_tunnel(tls_fd, s->cfg->host, s->cfg->port, s->cookie) < 0){
		close(tls_fd);
		return -1;
	}

	s->tls_fd = tls_fd;

	if(s->cfg->verbose)
		print("vpnfs: sslvpn-tunnel upgrade issued on TLS fd %d\n", tls_fd);

	return 0;
}

static int
fortinet_read_packet(VpnSession *s, uchar *buf, int maxlen)
{
	int n;
	n = read(s->tls_fd, buf, maxlen);
	if(n <= 0) return -1;
	if(s->cfg->verbose) print("vpnfs: rx packet len=%d\n", n);
	return n;
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	if(write(s->tls_fd, buf, len) != len) return -1;
	return len;
}

static void
fortinet_close(VpnSession *s)
{
	if(s->tls_fd >= 0){
		close(s->tls_fd);
		s->tls_fd = -1;
	}
	if(s->priv != nil){
		free(s->priv);
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
