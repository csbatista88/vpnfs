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
	uchar txbuf[2 * VPN_BUFSIZE];
	int txlen;
};

static ushort fcstab[256] = {
      0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
      0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
      0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
      0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
      0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
      0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
      0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
      0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
      0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
      0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
      0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
      0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
      0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
      0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
      0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
      0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
      0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
      0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
      0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
      0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
      0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
      0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
      0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
      0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
      0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
      0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
      0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
      0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
      0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
      0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
      0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
      0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#define PPP_INITFCS 0xffff
#define PPP_GOODFCS 0xf0b8
#define PPP_FLAG    0x7e
#define PPP_ESC     0x7d

static ushort
ppp_fcs16(ushort fcs, uchar *cp, int len)
{
	while(len--)
		fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];
	return fcs;
}

static int
ppp_hdlc_encode(uchar *src, int len, uchar *dst, int maxdst)
{
	ushort fcs;
	uchar *d = dst;
	uchar c;
	int i;

	if(maxdst < len * 2 + 10)
		return -1;

	fcs = ppp_fcs16(PPP_INITFCS, src, len);
	fcs ^= 0xffff;

	*d++ = PPP_FLAG;
	for(i = 0; i < len; i++){
		c = src[i];
		if(c == PPP_FLAG || c == PPP_ESC || c < 0x20){
			*d++ = PPP_ESC;
			*d++ = c ^ 0x20;
		}else{
			*d++ = c;
		}
	}

	c = fcs & 0xff;
	if(c == PPP_FLAG || c == PPP_ESC || c < 0x20){
		*d++ = PPP_ESC;
		*d++ = c ^ 0x20;
	}else{
		*d++ = c;
	}

	c = (fcs >> 8) & 0xff;
	if(c == PPP_FLAG || c == PPP_ESC || c < 0x20){
		*d++ = PPP_ESC;
		*d++ = c ^ 0x20;
	}else{
		*d++ = c;
	}

	*d++ = PPP_FLAG;
	return d - dst;
}

static int
ppp_hdlc_decode(uchar *src, int len, uchar *dst, int maxdst)
{
	uchar *d = dst;
	uchar c;
	int i;
	ushort fcs;

	for(i = 0; i < len; i++){
		c = src[i];
		if(c == PPP_FLAG)
			continue;
		if(c == PPP_ESC){
			if(i + 1 >= len)
				break;
			c = src[++i] ^ 0x20;
		}
		if(d - dst >= maxdst)
			return -1;
		*d++ = c;
	}

	if(d - dst < 4)
		return -1;

	fcs = ppp_fcs16(PPP_INITFCS, dst, d - dst);
	if(fcs != PPP_GOODFCS)
		return -1;

	return (d - dst) - 2;
}

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
	uchar hdr[6];
	uchar payload[VPN_BUFSIZE];
	uchar frame[VPN_BUFSIZE];
	int total, magic, len;

	if(readn(s->tls_fd, hdr, 6) != 6)
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

	total = (hdr[0] << 8) | hdr[1];
	magic = (hdr[2] << 8) | hdr[3];
	len   = (hdr[4] << 8) | hdr[5];

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

	/* RX (TLS -> STDIN of ip/ppp): Encapsulate Raw PPP into HDLC with FF 03 for ip/ppp -f */
	if(len + 2 > (int)sizeof(frame))
		return -1;

	frame[0] = 0xFF;
	frame[1] = 0x03;
	memmove(frame + 2, payload, len);

	return ppp_hdlc_encode(frame, len + 2, buf, maxlen);
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	FortinetPriv *priv = s->priv;
	uchar payload[VPN_BUFSIZE];
	uchar hdr[6];
	int i, start, lastflag, rawlen, rest;

	if(priv == nil)
		return -1;

	if(priv->txlen + len > (int)sizeof(priv->txbuf))
		priv->txlen = 0; /* Overflow: resync buffer */

	memmove(priv->txbuf + priv->txlen, buf, len);
	priv->txlen += len;

	start = -1;
	lastflag = -1;
	for(i = 0; i < priv->txlen; i++){
		if(priv->txbuf[i] != PPP_FLAG)
			continue;
		if(start >= 0 && i > start){
			rawlen = ppp_hdlc_decode(priv->txbuf + start, i - start, payload, sizeof(payload));
			if(rawlen >= 2){
				if(payload[0] == 0xFF && payload[1] == 0x03){
					memmove(payload, payload + 2, rawlen - 2);
					rawlen -= 2;
				}
				if(rawlen >= 2){
					hdr[0] = ((6 + rawlen) >> 8) & 0xFF;
					hdr[1] = (6 + rawlen) & 0xFF;
					hdr[2] = 0x50; /* 'P' */
					hdr[3] = 0x50; /* 'P' */
					hdr[4] = (rawlen >> 8) & 0xFF;
					hdr[5] = rawlen & 0xFF;

					if(write(s->tls_fd, hdr, 6) != 6 ||
					   write(s->tls_fd, payload, rawlen) != rawlen){
						priv->txlen = 0;
						return -1;
					}
				}
			}
		}
		start = i + 1;
		lastflag = i;
	}

	if(lastflag < 0)
		return len; /* Incomplete frame: keep accumulating */

	rest = priv->txlen - (lastflag + 1);
	memmove(priv->txbuf, priv->txbuf + lastflag + 1, rest);
	priv->txlen = rest;
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
