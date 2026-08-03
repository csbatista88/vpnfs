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
- **Network & Security Primitives:** Plan 9 manages TLS via `/net/tls` (`vpn_pushtls`) for HTTP authentication, and native UDP (`dial("udp!host!port", ...)` for binary tunnel connections.

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

## 3. Fortinet SSL-VPN Protocol Protocol Flow (UDP Mode)

```
[ vpnfs ]                                      [ FortiGate Gateway ]
    |                                                    |
    |--- TCP Dial & TLS Upgrade (port 10443) ----------->|
    |--- HTTP POST /remote/logincheck ------------------>|
    |    (username, credential, token/2FA)               |
    |<-- HTTP 200 OK + SVPNCOOKIE -----------------------|
    |                                                    |
    |--- Plan 9 UDP Dial (udp!host!10443) -------------->|
    |--- UDP clthello Handshake ------------------------>|
    |    [2-byte len] "GFtype\0clthello\0SVPNCOOKIE\0"   |
    |                 + cookie_val + "\0"                |
    |                                                    |
    |<-- UDP svrhello Handshake ("ok") ------------------|
    |                                                    |
    |<================ UDP Datagram ====================>|
    |              IP/PPP Packet Stream                  |
```

---

## 4. UDP `clthello` Handshake Layout

The Fortinet UDP tunnel connection begins by sending a `clthello` packet:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Big-Endian Payload Length (2 Bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   'G'   |   'F'   |   't'   |   'y'   |   'p'   |   'e'   |\0 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   'c'   |   'l'   |   't'   |   'h'   |   'e'   |   'l'   |...|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  "clthello\0"  | "SVPNCOOKIE\0" |  <cookie_value>        | \0 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Once the gateway accepts the cookie, it returns `svrhello` containing `"GFtype\0svrhello\0handshake\0ok\0"`, after which raw UDP datagrams are exchanged between the client and gateway.

---

## 5. Plan 9 Network Integration

Packets read from the UDP socket are forwarded to a Plan 9 `/pipe`. The pipe's endpoints interact with `ip/ppp` or `/net` stack drivers:

```
+---------------+     write_packet     +---------------+
|               |  ----------------->  |               |
| Plan 9 /pipe  |                      |    vpnfs      | ===> UDP Socket
|   (ip/ppp)    |  <-----------------  |               |
+---------------+      read_packet     +---------------+
```

---

## 6. Building & Running `vpnfs`

On 9front (Plan 9):

```sh
# Compile vpnfs
mk

# Run vpnfs (interactive token 2FA supported)
vpnfs -v -h remote.almavivadobrasil.com.br -p 10443 -u username -P password
```
