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
- **Security & Networking:** TLS connections managed via `tlsClient()` (`vpn_pushtls`), network connections via `dial()`, and pipe I/O via `pipe()`.

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

## 3. Fortinet SSL-VPN Protocol Protocol Flow (Dedicated Connections)

```
[ vpnfs ]                                      [ FortiGate Gateway ]
    |                                                    |
    |--- 1. TCP Dial & TLS Upgrade (Auth) -------------->|
    |--- HTTP POST /remote/logincheck ------------------>|
    |    (username, credential, token/2FA)               |
    |<-- HTTP 200 OK + SVPNCOOKIE -----------------------|
    |    [Close Auth TLS Connection]                     |
    |                                                    |
    |--- 2. Ephemeral TCP Dial & TLS Upgrade (XML) ----->|
    |--- HTTP GET /remote/fortisslvpn_xml?dual_stack=1 ->|
    |    (Cookie: SVPNCOOKIE=..., Connection: close)     |
    |<-- XML Config Body (<assigned-addr>, <dns>) -------|
    |    [Close Ephemeral XML TLS Connection]            |
    |                                                    |
    |--- 3. Dedicated TCP Dial & TLS Upgrade (Tunnel) ->|
    |--- HTTP GET /remote/sslvpn-tunnel ---------------->|
    |                                                    |
    |<================ TLS Stream Datagram =============>|
    |              IP/PPP Packet Stream                  |
```

---

## 4. XML Network Parameter Extraction

During `fortinet_fetch_config()`, `vpnfs` opens a dedicated, ephemeral TLS connection to query `/remote/fortisslvpn_xml?dual_stack=1` with `Connection: close`, preventing HTTP pipeline timeouts (`408`).
Extracted fields saved to `FortinetPriv`:
- Virtual IPv4 address: `<assigned-addr ipv4="x.x.x.x"/>`
- Primary DNS server: `<dns ip="y.y.y.y"/>`

In verbose (`-v`) mode, the full XML response body is printed to console.

---

## 5. Plan 9 Network Integration

Packets read from the TLS tunnel socket are forwarded to a Plan 9 `/pipe`. The pipe's endpoints interact with `ip/ppp` or `/net` stack drivers:

```
+---------------+     write_packet     +---------------+
|               |  ----------------->  |               |
| Plan 9 /pipe  |                      |    vpnfs      | ===> TLS Socket
|   (ip/ppp)    |  <-----------------  |               |
+---------------+      read_packet     +---------------+
```

---

## 6. Building & Running `vpnfs`

On 9front (Plan 9):

```sh
# Compile vpnfs
mk

# Run vpnfs (interactive token 2FA & verbose XML dump supported)
vpnfs -v -h remote.almavivadobrasil.com.br -p 10443 -u username -P password
```
