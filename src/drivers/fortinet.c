#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "../vpnfs.h"

#define PPP_FLAG     0x7E
#define PPP_ESCAPE   0x7D
#define PPP_TRANS    0x20
#define PPP_INITFCS  0xFFFF
#define PPP_GOODFCS  0xF0B8

static ushort fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcce, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbe6, 0xea6f, 0xd8f4, 0xc97d,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfe47, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3ad3, 0x4e64, 0x5fe5, 0x6d76, 0x7cf7,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7ee7, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bc5, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ed3, 0x2f5a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0base, 0x3de3, 0x2c6a, 0x1ed1, 0x0f58
};

typedef struct FortinetPriv FortinetPriv;
struct FortinetPriv {
	char ip[64];
	char dns1[64];
	char dns2[64];
};

static ushort
ppp_fcs16(ushort fcs, uchar *cp, int len)
{
	while(len-- > 0)
		fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];
	return fcs;
}

static int
ppp_hdlc_encode(uchar *src, int srclen, uchar *dst, int dstmax)
{
	int i, d;
	ushort fcs;
	uchar c, fcsbuf[2];

	if(dstmax < 6)
		return -1;

	fcs = ppp_fcs16(PPP_INITFCS, src, srclen) ^ 0xFFFF;
	fcsbuf[0] = fcs & 0xFF;
	fcsbuf[1] = (fcs >> 8) & 0xFF;

	d = 0;
	dst[d++] = PPP_FLAG;

	for(i = 0; i < srclen; i++){
		c = src[i];
		if(c == PPP_FLAG || c == PPP_ESCAPE || c < 0x20){
			if(d + 2 >= dstmax) return -1;
			dst[d++] = PPP_ESCAPE;
			dst[d++] = c ^ PPP_TRANS;
		}else{
			if(d + 1 >= dstmax) return -1;
			dst[d++] = c;
		}
	}

	for(i = 0; i < 2; i++){
		c = fcsbuf[i];
		if(c == PPP_FLAG || c == PPP_ESCAPE || c < 0x20){
			if(d + 2 >= dstmax) return -1;
			dst[d++] = PPP_ESCAPE;
			dst[d++] = c ^ PPP_TRANS;
		}else{
			if(d + 1 >= dstmax) return -1;
			dst[d++] = c;
		}
	}

	if(d + 1 >= dstmax) return -1;
	dst[d++] = PPP_FLAG;
	return d;
}

static int
ppp_hdlc_decode(uchar *src, int srclen, uchar *dst, int dstmax)
{
	int i, d, escaped;
	uchar c;
	ushort fcs;

	d = 0;
	escaped = 0;

	for(i = 0; i < srclen; i++){
		c = src[i];
		if(c == PPP_FLAG)
			continue;
		if(c == PPP_ESCAPE){
			escaped = 1;
			continue;
		}
		if(escaped){
			c ^= PPP_TRANS;
			escaped = 0;
		}
		if(d < dstmax)
			dst[d++] = c;
	}

	if(d < 2)
		return d; /* Se nao houver bytes suficientes para FCS, retorna payload cru */

	/* Valida e remove o FCS-16 final (2 bytes) */
	fcs = ppp_fcs16(PPP_INITFCS, dst, d);
	if(fcs == PPP_GOODFCS){
		d -= 2; /* Remove os 2 bytes de FCS */
	}

	return d;
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
fortinet_fetch_config(VpnSession *s, int tls_fd)
{
	char req[512];
	char resp[4096];
	char *ip, *dns1, *body;
	int n, total;
	FortinetPriv *priv = s->priv;

	if(s->cookie[0] == '\0')
		return -1;

	if(s->cfg->verbose)
		print("vpnfs: fetching XML configuration on authenticated TLS connection...\n");

	snprint(req, sizeof(req),
		"GET /remote/fortisslvpn_xml?dual_stack=1 HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 SV1\r\n"
		"Cookie: %s\r\n"
		"Connection: close\r\n\r\n",
		s->cfg->host, s->cookie);

	if(write(tls_fd, req, strlen(req)) != strlen(req)){
		if(s->cfg->verbose)
			fprint(2, "vpnfs: warning: XML config request write failed\n");
		return 0;
	}

	memset(resp, 0, sizeof(resp));
	total = 0;

	while(total < sizeof(resp) - 1){
		n = read(tls_fd, resp + total, sizeof(resp) - 1 - total);
		if(n <= 0)
			break;
		total += n;
	}
	resp[total] = '\0';

	body = strstr(resp, "\r\n\r\n");
	if(body != nil){
		body += 4;
		if(cistrstr(resp, "transfer-encoding: chunked") != nil)
			unchunk(body);
	}else{
		body = resp;
	}

	if(s->cfg->verbose){
		print("vpnfs: XML config response (%d bytes):\n%s\n", total, body);
	}

	if(strstr(resp, "200 OK") == nil){
		if(s->cfg->verbose)
			fprint(2, "vpnfs: XML configuration endpoint returned non-200 (proceeding with tunnel)\n");
		return 0;
	}

	ip = extract_xml_tag(body, "assigned-addr", "ipv4");
	dns1 = extract_xml_tag(body, "dns", "ip");

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

	cookie_val = extract_cookie(resp, "SVPNCOOKIE");

	if(cookie_val == nil || strstr(resp, "tokeninfo=") != nil || strstr(resp, "2fa") != nil){
		char *magic_val = extract_cookie(resp, "magic");
		char *reqid_val = extract_cookie(resp, "reqid");
		char *polid_val = extract_cookie(resp, "polid");

		if(cookie_val != nil) free(cookie_val);
		close(tls_fd);

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

		if(n <= 0){ close(tls_fd); return -1; }

		cookie_val = extract_cookie(resp, "SVPNCOOKIE");
	}

	if(cookie_val == nil){
		close(tls_fd);
		fprint(2, "vpnfs: SVPNCOOKIE not found\n");
		return -1;
	}

	snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", cookie_val);
	free(cookie_val);

	if(s->cfg->verbose)
		print("vpnfs: authenticated successfully (got SVPNCOOKIE)\n");

	/* Busca o XML de configuracao na MESMA conexao TLS da autenticacao */
	fortinet_fetch_config(s, tls_fd);
	close(tls_fd);

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
	uchar hdr[2];
	uchar payload[VPN_BUFSIZE];
	int len;

	if(readn(s->tls_fd, hdr, 2) != 2)
		return -1;

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
		return 0; /* Retorna 0 para o main loop ignorar e continuar a leitura */
	}

	/* TRADUÇÃO: Encapsula o PPP Raw em quadro HDLC (RFC 1662) com FCS-16 para o ppp(8) do 9front */
	return ppp_hdlc_encode(payload, len, buf, maxlen);
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	uchar hdr[2];
	uchar payload[VPN_BUFSIZE];
	int rawlen;

	/* TRADUÇÃO: Decodifica o quadro HDLC do ppp(8) extraindo o payload PPP Raw */
	rawlen = ppp_hdlc_decode(buf, len, payload, sizeof(payload));
	if(rawlen <= 0)
		return -1;

	/* Encapsulamento Fortinet (2 bytes de tamanho Big-Endian + payload PPP Raw) */
	hdr[0] = (rawlen >> 8) & 0xFF;
	hdr[1] = rawlen & 0xFF;

	if(write(s->tls_fd, hdr, 2) != 2)
		return -1;

	if(write(s->tls_fd, payload, rawlen) != rawlen)
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
