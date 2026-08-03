#include <u.h>
#include <libc.h>
#include <mp.h>
#include <libsec.h>
#include "../vpnfs.h"

typedef struct FortinetPriv FortinetPriv;
struct FortinetPriv {
	int auth_fd;
};

static int
read_exact(int fd, uchar *buf, int n)
{
	int got, total;

	total = 0;
	while(total < n){
		got = read(fd, buf + total, n - total);
		if(got <= 0)
			return -1;
		total += got;
	}
	return total;
}

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

	/* Find delimiter: ';' or '\r' or '\n' or '\0' */
	end = p;
	while(*end && *end != ';' && *end != '\r' && *end != '\n')
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

	print("%s", prompt);
	fd = open("/dev/cons", OREAD);
	if(fd < 0)
		return nil;

	n = read(fd, buf, buflen - 1);
	close(fd);

	if(n <= 0)
		return nil;

	buf[n] = '\0';
	while(n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')){
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
	char body[512];
	char resp[4096];
	char *cookie_val;
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
	if(raw_fd < 0)
		return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0)
		return -1;

	if(s->cfg->verbose)
		print("vpnfs: sending login request to /remote/logincheck...\n");

	n = vpn_http_post(tls_fd, s->cfg->host, "remote/logincheck", body, resp, sizeof(resp));
	close(tls_fd);

	if(n <= 0){
		fprint(2, "vpnfs: fortinet_auth failed to receive HTTP response\n");
		return -1;
	}

	cookie_val = extract_cookie(resp, "SVPNCOOKIE");

	/* Check if 2FA / FortiToken is required */
	if(cookie_val == nil || strstr(resp, "tokeninfo=") != nil || strstr(resp, "2fa") != nil){
		if(cookie_val != nil){
			free(cookie_val);
			cookie_val = nil;
		}

		if(s->cfg->verbose)
			print("vpnfs: 2FA challenge detected (tokeninfo/no cookie)\n");

		if(s->cfg->token != nil && *s->cfg->token != '\0'){
			token_str = s->cfg->token;
		}else{
			if(prompt_token("FortiToken Code: ", token_buf, sizeof(token_buf)) == nil){
				fprint(2, "vpnfs: failed to read token code from console\n");
				return -1;
			}
			token_str = token_buf;
		}

		if(s->cfg->realm != nil && *s->cfg->realm != '\0')
			snprint(body, sizeof(body), "username=%s&credential=%s&realm=%s&code=%s&ajax=1",
				s->cfg->user, s->cfg->pass, s->cfg->realm, token_str);
		else
			snprint(body, sizeof(body), "username=%s&credential=%s&code=%s&ajax=1",
				s->cfg->user, s->cfg->pass, token_str);

		if(s->cfg->verbose)
			print("vpnfs: sending 2FA token verification to /remote/logincheck...\n");

		raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
		if(raw_fd < 0)
			return -1;

		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd < 0)
			return -1;

		n = vpn_http_post(tls_fd, s->cfg->host, "remote/logincheck", body, resp, sizeof(resp));
		close(tls_fd);

		if(n <= 0){
			fprint(2, "vpnfs: fortinet_auth failed to receive 2FA HTTP response\n");
			return -1;
		}

		cookie_val = extract_cookie(resp, "SVPNCOOKIE");
	}

	if(cookie_val == nil){
		fprint(2, "vpnfs: SVPNCOOKIE not found in login response\n");
		if(s->cfg->verbose)
			fprint(2, "vpnfs: response:\n%s\n", resp);
		return -1;
	}

	snprint(s->cookie, sizeof(s->cookie), "SVPNCOOKIE=%s", cookie_val);
	free(cookie_val);

	if(s->cfg->verbose)
		print("vpnfs: authenticated successfully (got SVPNCOOKIE)\n");

	/* Fetch /remote/fortisslvpn_xml to validate/activate session on FortiOS */
	if(s->cfg->verbose)
		print("vpnfs: fetching /remote/fortisslvpn_xml...\n");

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd >= 0){
		tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
		if(tls_fd >= 0){
			char req[512];
			int reqlen;

			reqlen = snprint(req, sizeof(req),
				"GET /remote/fortisslvpn_xml HTTP/1.1\r\n"
				"Host: %s\r\n"
				"User-Agent: Mozilla/5.0 SV1\r\n"
				"Cookie: %s\r\n"
				"Connection: close\r\n"
				"\r\n",
				s->cfg->host, s->cookie);

			write(tls_fd, req, reqlen);
			while(read(tls_fd, resp, sizeof(resp)) > 0)
				;
			close(tls_fd);
		}
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

	if(s->cfg->verbose)
		print("vpnfs: establishing SSL-VPN binary tunnel to %s...\n", s->cfg->host);

	raw_fd = vpn_dial(s->cfg->host, s->cfg->port);
	if(raw_fd < 0)
		return -1;

	tls_fd = vpn_pushtls(raw_fd, s->cfg->host);
	if(tls_fd < 0)
		return -1;

	if(vpn_http_get_tunnel(tls_fd, s->cfg->host, s->cookie) < 0){
		close(tls_fd);
		return -1;
	}

	s->tls_fd = tls_fd;

	if(s->cfg->verbose)
		print("vpnfs: tunnel connection established on fd %d\n", tls_fd);

	return 0;
}

static int
fortinet_read_packet(VpnSession *s, uchar *buf, int maxlen)
{
	uchar hdr[FORTINET_HDR_LEN];
	int payload_len, frame_len;

	if(read_exact(s->tls_fd, hdr, FORTINET_HDR_LEN) < 0)
		return -1;

	/* Verify Fortinet 12-byte header magic: 0x50 0x41 ('P', 'A') */
	if(hdr[0] != FORTINET_HDR_MAGIC1 || hdr[1] != FORTINET_HDR_MAGIC2){
		fprint(2, "vpnfs: invalid Fortinet header magic: 0x%02x 0x%02x\n", hdr[0], hdr[1]);
		return -1;
	}

	frame_len = (hdr[2] << 8) | hdr[3];
	payload_len = frame_len - FORTINET_HDR_LEN;

	if(payload_len < 0 || payload_len > maxlen){
		fprint(2, "vpnfs: invalid packet payload length: %d\n", payload_len);
		return -1;
	}

	if(payload_len > 0){
		if(read_exact(s->tls_fd, buf, payload_len) < 0)
			return -1;
	}

	return payload_len;
}

static int
fortinet_write_packet(VpnSession *s, uchar *buf, int len)
{
	uchar frame[VPN_BUFSIZE];
	int frame_len;

	frame_len = FORTINET_HDR_LEN + len;
	if(frame_len > sizeof(frame)){
		fprint(2, "vpnfs: packet payload exceeds buffer size (%d > %d)\n", len, (int)sizeof(frame) - FORTINET_HDR_LEN);
		return -1;
	}

	/* Pack Fortinet 12-byte Header */
	frame[0] = FORTINET_HDR_MAGIC1; /* 0x50 ('P') */
	frame[1] = FORTINET_HDR_MAGIC2; /* 0x41 ('A') */
	frame[2] = (frame_len >> 8) & 0xFF;
	frame[3] = frame_len & 0xFF;
	frame[4] = 0x01;                /* Packet flags / control */
	memset(frame + 5, 0, 7);         /* Reserved fields */

	/* Payload */
	memmove(frame + FORTINET_HDR_LEN, buf, len);

	if(write(s->tls_fd, frame, frame_len) != frame_len){
		fprint(2, "vpnfs: write packet failed: %r\n");
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
