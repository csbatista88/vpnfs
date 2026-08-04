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

static void
unchunk(char *body)
{
	char *src, *dst, *e;
	long n;

	src = dst = body;
	while(*src != '\0'){
		n = strtol(src, &e, 16);
		if(n <= 0)
			break;
		src = e;
		while(*src == '\r' || *src == '\n')
			src++;
		memmove(dst, src, n);
		dst += n;
		src += n;
		while(*src == '\r' || *src == '\n')
			src++;
	}
	*dst = '\0';
}

static char*
extract_cookie(char *resp, char *cookie_name)
{
	char *hdr_end, *p, *end, *val;
	int n;

	if(resp == nil || cookie_name == nil)
		return nil;

	hdr_end = strstr(resp, "\r\n\r\n");
	p = resp;
	n = strlen(cookie_name);

	while(p != nil){
		p = strstr(p, cookie_name);
		if(p == nil)
			break;

		/* Only care about HTTP headers, not HTML/JS body. */
		if(hdr_end != nil && p >= hdr_end)
			break;

		p += n;
		if(*p == '=')
			p++;

		end = p;
		while(*end != '\0' &&
		      *end != ';' &&
		      *end != '\r' &&
		      *end != '\n' &&
		      *end != '&' &&
		      *end != '"' &&
		      *end != ' ')
			end++;

		if(end > p){
			val = malloc(end - p + 1);
			if(val == nil)
				return nil;
			memmove(val, p, end - p);
			val[end - p] = '\0';
			return val;
		}

		/* Empty cookie value; skip and keep looking. */
		p = end;
		if(*p != '\0')
			p++;
		else
			break;
	}

	return nil;
}

static char*
extract_field(char *resp, char *name)
{
	char *p, *end, *val;
	int n;

	if(resp == nil || name == nil)
		return nil;

	p = resp;
	n = strlen(name);

	while((p = strstr(p, name)) != nil){
		p += n;
		if(*p == '=')
			p++;

		end = p;
		while(*end != '\0' &&
		      *end != ',' &&
		      *end != '&' &&
		      *end != '\r' &&
		      *end != '\n' &&
		      *end != '"')
			end++;

		if(end > p){
			val = malloc(end - p + 1);
			if(val == nil)
				return nil;
			memmove(val, p, end - p);
			val[end - p] = '\0';
			return val;
		}

		p = end;
		if(*p != '\0')
			p++;
		else
			break;
	}

	return nil;
}

static char*
extract_xml_tag(char *xml, char *tag, char *attr)
{
	char tag_start[128], attr_start[128];
	char *p, *e, *end, *val;
	int tag_len, attr_len;

	snprint(tag_start, sizeof(tag_start), "<%s ", tag);
	tag_len = strlen(tag_start);

	snprint(attr_start, sizeof(attr_start), "%s=", attr);
	attr_len = strlen(attr_start);

	p = xml;
	while((p = strstr(p, tag_start)) != nil){
		e = strchr(p, '>');
		if(e == nil)
			break;

		p += tag_len;
		while(p < e){
			if(strncmp(p, attr_start, attr_len) == 0){
				p += attr_len;
				if(*p == '\'' || *p == '"')
					p++;
				end = p;
				while(end < e && *end != '\'' && *end != '"' && *end != ' ' && *end != '>')
					end++;
				val = malloc(end - p + 1);
				if(val == nil)
					return nil;
				memmove(val, p, end - p);
				val[end - p] = '\0';
				return val;
			}
			p++;
		}
		p = e + 1;
	}
	return nil;
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
fortinet_auth(VpnSession *s)
{
	int raw_fd, tls_fd, n, status;
	char body[2048];
	char resp[8192];
	char *u, *p, *r, *tenc, *cookie_val;
	char *magic_val, *reqid_val, *polid_val;
	char token_buf[128];
	char *token_str;

	if(s->cfg->user == nil || s->cfg->pass == nil)
		return -1;

	u = vpn_urlencode(s->cfg->user);
	p = vpn_urlencode(s->cfg->pass);
	r = vpn_urlencode(s->cfg->realm != nil ? s->cfg->realm : "");

	if(u == nil || p == nil || r == nil){
		free(u); free(p); free(r);
		return -1;
	}

	snprint(body, sizeof(body),
		"username=%s&credential=%s&realm=%s&ajax=1&just_logged_in=1",
		u, p, r);

	if(s->cfg->verbose)
		print("vpnfs: connecting to %s:%s for authentication...\n",
			s->cfg->host, s->cfg->port);

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0){
		free(u); free(p); free(r);
		return -1;
	}

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0){
		close(raw_fd);
		free(u); free(p); free(r);
		return -1;
	}

	n = vpn_http_request(tls_fd, s->cfg->host, s->cfg->port,
	                     "POST", "/remote/logincheck",
	                     "application/x-www-form-urlencoded",
	                     body, nil, resp, sizeof(resp));

	close(tls_fd);

	free(u); free(p); free(r);

	if(n <= 0){
		fprint(2, "vpnfs: logincheck request failed\n");
		return -1;
	}

	status = vpn_http_status(resp);
	if(s->cfg->verbose)
		print("vpnfs: logincheck HTTP status %d\n", status);

	cookie_val = extract_cookie(resp, "SVPNCOOKIE");

	if(cookie_val == nil || strstr(resp, "tokeninfo=") != nil){
		magic_val = extract_field(resp, "magic");
		reqid_val = extract_field(resp, "reqid");
		polid_val = extract_field(resp, "polid");

		if(s->cfg->token != nil && s->cfg->token[0] != '\0'){
			token_str = s->cfg->token;
		}else{
			if(prompt_token("FortiToken Code: ", token_buf, sizeof(token_buf)) == nil){
				free(cookie_val); free(magic_val); free(reqid_val); free(polid_val);
				return -1;
			}
			token_str = token_buf;
		}

		u = vpn_urlencode(s->cfg->user);
		p = vpn_urlencode(s->cfg->pass);
		r = vpn_urlencode(s->cfg->realm != nil ? s->cfg->realm : "");
		tenc = vpn_urlencode(token_str);

		if(u == nil || p == nil || r == nil || tenc == nil){
			free(u); free(p); free(r); free(tenc);
			free(cookie_val); free(magic_val); free(reqid_val); free(polid_val);
			return -1;
		}

		snprint(body, sizeof(body),
			"username=%s&credential=%s&code=%s&realm=%s"
			"&magic=%s&reqid=%s&polid=%s&ajax=1",
			u, p, tenc, r,
			magic_val != nil ? magic_val : "",
			reqid_val != nil ? reqid_val : "",
			polid_val != nil ? polid_val : "");

		free(u); free(p); free(r); free(tenc);
		free(cookie_val); free(magic_val); free(reqid_val); free(polid_val);

		raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
		if(raw_fd < 0)
			return -1;

		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd < 0){
			close(raw_fd);
			return -1;
		}

		n = vpn_http_request(tls_fd, s->cfg->host, s->cfg->port,
		                     "POST", "/remote/logincheck",
		                     "application/x-www-form-urlencoded",
		                     body, nil, resp, sizeof(resp));

		close(tls_fd);

		if(n <= 0){
			fprint(2, "vpnfs: second-stage logincheck failed\n");
			return -1;
		}

		status = vpn_http_status(resp);
		if(s->cfg->verbose)
			print("vpnfs: second-stage logincheck HTTP status %d\n", status);

		cookie_val = extract_cookie(resp, "SVPNCOOKIE");
	}

	if(cookie_val == nil){
		fprint(2, "vpnfs: SVPNCOOKIE not found\n");
		if(s->cfg->verbose)
			fprint(2, "vpnfs: last login response:\n%s\n", resp);
		return -1;
	}

	snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", cookie_val);
	free(cookie_val);

	if(s->cfg->verbose)
		print("vpnfs: authenticated successfully (got SVPNCOOKIE)\n");

	return 0;
}

static int
fortinet_fetch_config(VpnSession *s)
{
	int raw_fd, tls_fd, n, status;
	char resp[8192];
	char *body, *ip, *dns1;
	FortinetPriv *priv = s->priv;

	if(s->cookie[0] == '\0')
		return -1;

	if(s->cfg->verbose)
		print("vpnfs: fetching XML configuration on new TLS connection...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0)
		return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0){
		close(raw_fd);
		return -1;
	}

	n = vpn_http_request(tls_fd, s->cfg->host, s->cfg->port,
	                     "GET", "/remote/fortisslvpn_xml",
	                     nil, nil, s->cookie, resp, sizeof(resp));

	close(tls_fd);

	if(n <= 0){
		fprint(2, "vpnfs: XML config request failed\n");
		return -1;
	}

	status = vpn_http_status(resp);

	if(status != 200){
		if(s->cfg->verbose)
			print("vpnfs: XML config without dual_stack returned HTTP %d; retrying with dual_stack\n",
				status);

		raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
		if(raw_fd < 0)
			return -1;

		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd < 0){
			close(raw_fd);
			return -1;
		}

		n = vpn_http_request(tls_fd, s->cfg->host, s->cfg->port,
		                     "GET", "/remote/fortisslvpn_xml?dual_stack=1",
		                     nil, nil, s->cookie, resp, sizeof(resp));

		close(tls_fd);

		if(n <= 0){
			fprint(2, "vpnfs: dual_stack XML config request failed\n");
			return -1;
		}

		status = vpn_http_status(resp);
	}

	if(status != 200){
		fprint(2, "vpnfs: XML configuration failed with HTTP %d\n", status);
		if(s->cfg->verbose)
			fprint(2, "vpnfs: response:\n%s\n", resp);
		return -1;
	}

	body = strstr(resp, "\r\n\r\n");
	if(body != nil){
		body += 4;
		if(cistrstr(resp, "transfer-encoding: chunked") != nil)
			unchunk(body);
	}else{
		body = resp;
	}

	if(s->cfg->verbose)
		print("vpnfs: XML config response (%d bytes):\n%s\n", n, body);

	ip = extract_xml_tag(body, "assigned-addr", "ipv4");
	dns1 = extract_xml_tag(body, "dns", "ip");

	if(ip != nil){
		snprint(priv->ip, sizeof(priv->ip), "%s", ip);
		if(s->cfg->verbose)
			print("vpnfs: assigned virtual IP: %s\n", ip);
		free(ip);
	}

	if(dns1 != nil){
		snprint(priv->dns1, sizeof(priv->dns1), "%s", dns1);
		if(s->cfg->verbose)
			print("vpnfs: assigned DNS server: %s\n", dns1);
		free(dns1);
	}

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

	if(fortinet_fetch_config(s) < 0){
		fprint(2, "vpnfs: unable to fetch Fortinet XML configuration\n");
		return -1;
	}

	if(s->cfg->verbose)
		print("vpnfs: opening dedicated TLS connection for tunnel upgrade...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0)
		return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0){
		close(raw_fd);
		return -1;
	}

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
	uchar hdr[2];
	uchar payload[VPN_BUFSIZE];
	int len;

	if(readn(s->tls_fd, hdr, 2) != 2)
		return -1;

	/* Intercept HTTP error status if FortiGate rejects the tunnel upgrade */
	if(hdr[0] == 'H' && hdr[1] == 'T'){
		char errbuf[1024];
		int n;
		errbuf[0] = 'H';
		errbuf[1] = 'T';
		n = read(s->tls_fd, errbuf + 2, sizeof(errbuf) - 3);
		if(n > 0) errbuf[2 + n] = '\0';
		else errbuf[2] = '\0';
		fprint(2, "vpnfs: tunnel request rejected by FortiGate:\n%s\n", errbuf);
		return -1;
	}

	len = (hdr[0] << 8) | hdr[1];

	if(len < 0 || len > sizeof(payload))
		return -1;

	if(len > 0){
		if(readn(s->tls_fd, payload, len) != len)
			return -1;
	}

	/* FILTRO: Intercepta e descarta pacotes de controle/heartbeat GFtype da Fortinet */
	if(len >= 6 && memcmp(payload, "GFtype", 6) == 0){
		if(s->cfg->verbose)
			print("vpnfs: filtered Fortinet GFtype heartbeat packet (%d bytes)\n", len);
		return 0;
	}

	/* Fortinet TLS envia PPP Raw. Repassa o payload PPP Raw diretamente para o ip/ppp */
	if(len > maxlen)
		return -1;

	memmove(buf, payload, len);
	return len;
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	uchar hdr[2];

	if(len <= 0 || len > VPN_BUFSIZE)
		return -1;

	/* Encapsulamento Fortinet (2 bytes de tamanho Big-Endian + payload PPP Raw do ip/ppp) */
	hdr[0] = (len >> 8) & 0xFF;
	hdr[1] = len & 0xFF;

	if(write(s->tls_fd, hdr, 2) != 2)
		return -1;

	if(write(s->tls_fd, buf, len) != len)
		return -1;

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
