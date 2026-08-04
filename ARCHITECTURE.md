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

## 2. Modular Architecture (`VpnDriver`)

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

## 3. Protocol Flow & Framing Translation Layer

```
[ FortiGate Gateway ]                       [ vpnfs ]                              [ Plan 9 ppp(8) Daemon ]
         |                                      |                                             |
         |<--- 1. TCP Dial & TLS (Port 10443) ->|                                             |
         |<--- HTTP POST /remote/logincheck ----|                                             |
         |---> HTTP 200 OK + SVPNCOOKIE --------|                                             |
         |                                      |                                             |
         |<--- HTTP GET /remote/fortisslvpn_xml |                                             |
         |---> XML Config (Decoded via unchunk)-|                                             |
         |     [Close Auth TLS Connection]      |                                             |
         |                                      |                                             |
         |<--- 2. Dedicated TCP Dial & TLS ---->|                                             |
         |<--- HTTP GET /remote/sslvpn-tunnel --|                                             |
         |                                      |                                             |
         |<=== PPP Raw + 2-byte Length Header =>|                                             |
         |     (Filter out GFtype heartbeats)   |<=== HDLC Async Frames (RFC 1662 + FCS) ====>|
         |                                      |     read/write via /srv/vpnfs               |
```

---

## 4. Key Components

### A. GFtype Heartbeat Filter
Fortinet gateways periodically inject proprietary keepalive packets starting with `"GFtype\0heartbeat\0"`. `fortinet_read_packet()` intercepts and drops these packets (returning `0` to cause the `main.c` packet loop to `continue`), preventing HDLC CRC corruption in `ppp(8)`.

### B. RFC 1662 HDLC Framer / Unframer
- **`ppp_hdlc_encode()`:** Translates Fortinet PPP Raw payloads into standard HDLC Async frames (`0x7E` flags, `0x7D` byte escaping, 16-bit FCS CRC) before writing to `/srv/vpnfs.out`.
- **`ppp_hdlc_decode()`:** Un-escapes HDLC frames received from `/srv/vpnfs.in` and strips the FCS CRC to extract the PPP Raw payload before adding the 2-byte Big-Endian length header for TLS transmission.

### C. Native `/srv` Posting
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
