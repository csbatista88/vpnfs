# `vpnfs` Architecture & Specification

`vpnfs` is a native 9front (Plan 9) VPN client and file/network driver interface. It enables secure network tunneling over HTTPS and UDP/DTLS protocols, starting with support for **Fortinet SSL-VPN**.

---

## 1. System Context & Environment (9front Native)

- **Compilation Toolchain:** 9front C compiler (`6c` / `6l` on amd64) and `mk` build utility.
- **Header Order:** Standard Plan 9 C order:
  ```c
  #include <u.h>
  #include <libc.h>
  #include "vpnfs.h"
  ```
- **Security & Networking:** TLS connections managed via `tlsClient()` (`vpn_pushtls`), network connections via `dial()`, and pipe I/O exposed to `/srv/vpnfs` via `vpn_post_srv()`.

---

## 2. OpenConnect 3-Stage TLS Connection Lifecycle

`vpnfs` implements OpenConnect's 3-stage TLS lifecycle for Fortinet SSL-VPN:

```
[ Stage 1: Auth ]
   POST /remote/logincheck (URL Encoded Params) ---> SVPNCOOKIE ---> Close TLS Conn 1/2

[ Stage 2: Session Setup & XML Config ]
   GET /remote/fortisslvpn_xml (New TLS Conn 3) ---> Parse IP/DNS ---> Close TLS Conn 3

[ Stage 3: Tunnel Upgrade ]
   GET /remote/sslvpn-tunnel (New TLS Conn 4) ---> Keep-Alive ---> Binary PPP Exchange
```

---

## 3. Modular Architecture (`VpnDriver`)

`vpnfs` is designed around a modular driver interface defined in `src/vpnfs.h`:

```c
struct VpnDriver {
	char *name;
	int  (*init)(VpnSession *s);
	int  (*auth)(VpnSession *s);
	int  (*connect_tunnel)(VpnSession *s);
	int  (*read_packet)(VpnSession *s, uchar *buf, int maxlen);
	int  (*write_packet)(VpnSession *s, uchar *buf, int len);
	void (*close)(VpnSession *s);
};
```

---

## 4. Key Components

### A. URL Encoding & Header Engine
- **`vpn_urlencode()`:** Encodes credentials, realms, and 2FA tokens (`username=%s&credential=%s...`).
- **`extract_cookie()`:** Restricted exclusively to HTTP response headers (before `\r\n\r\n`), ignoring empty clearing cookies.
- **`extract_field()`:** Field extractor for comma-separated 2FA challenge responses (`magic`, `reqid`, `polid`).

### B. GFtype Heartbeat Filter
Fortinet gateways periodically inject proprietary keepalive packets starting with `"GFtype\0heartbeat\0"`. `fortinet_read_packet()` intercepts and drops these packets (returning `0` to cause the `main.c` packet loop to `continue`), preventing HDLC CRC corruption in `ppp(8)`.

### C. RFC 1662 HDLC Framer / Unframer
- **`ppp_hdlc_encode()`:** Translates Fortinet PPP Raw payloads into standard HDLC Async frames (`0x7E` flags, `0x7D` byte escaping, 16-bit FCS CRC) before writing to `/srv/vpnfs.out`.
- **`ppp_hdlc_decode()`:** Un-escapes HDLC frames received from `/srv/vpnfs.in` and strips the FCS CRC to extract the PPP Raw payload before adding the 2-byte Big-Endian length header for TLS transmission.

### D. Native `/srv` Posting
`vpn_create_pipes()` posts `/srv/vpnfs.in`, `/srv/vpnfs.out`, and `/srv/vpnfs` using standard Plan 9 `create("/srv/<name>", OWRITE, 0666)` and `fprint(sfd, "%d", fd)`, enabling `ppp(8)` to attach directly to the tunnel.

---

## 5. Building & Running `vpnfs` on 9front

```sh
# 1. Compile vpnfs
mk

# 2. Start vpnfs in background
vpnfs -v -h remote.almavivadobrasil.com.br -p 10443 -u csbatista -P password &

# 3. Attach Plan 9 ppp(8) daemon
ppp /srv/vpnfs.in /srv/vpnfs.out
```
