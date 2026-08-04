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

### Module Breakdown
- `src/main.c`: CLI parsing (`ARGBEGIN`/`ARGEND`), session setup, and bi-directional worker process spawning via `rfork(RFPROC|RFMEM)`.
- `src/net_plan9.c`: Low-level network primitives (`vpn_dial`, `vpn_pushtls`, HTTP request generators, and `vpn_create_pipes`).
- `src/drivers/fortinet.c`: Implementation of the Fortinet SSL-VPN driver.

---

## 3. Fortinet SSL-VPN Protocol Protocol Flow (TLS Reuse Mode)

```
[ vpnfs ]                                      [ FortiGate Gateway ]
    |                                                    |
    |--- TCP Dial & TLS Upgrade (port 10443) ----------->|
    |--- HTTP POST /remote/logincheck ------------------>|
    |    (username, credential, token/2FA)               |
    |<-- HTTP 200 OK + SVPNCOOKIE -----------------------|
    |                                                    |
    | (Maintain Active TLS Socket)                       |
    |--- HTTP GET /remote/fortisslvpn_xml?dual_stack=1 ->|
    |<-- XML Config (<assigned-addr>, <dns>) ------------|
    |                                                    |
    |--- HTTP GET /remote/sslvpn-tunnel ---------------->|
    |                                                    |
    |<================ TLS Stream Datagram =============>|
    |              IP/PPP Packet Stream                  |
```

---

## 4. XML Network Parameter Extraction

During `fortinet_fetch_config()`, `vpnfs` requests `/remote/fortisslvpn_xml?dual_stack=1` over the active TLS connection and extracts:
- Virtual IPv4 address: `<assigned-addr ipv4="x.x.x.x"/>`
- Primary DNS server: `<dns ip="y.y.y.y"/>`

In verbose (`-v`) mode, the full XML response body is printed to console to aid in Plan 9 network configuration tuning.

---

## 5. Plan 9 Network Integration

Packets read from the TLS socket are forwarded to a Plan 9 `/pipe`. The pipe's endpoints interact with `ip/ppp` or `/net` stack drivers:

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
