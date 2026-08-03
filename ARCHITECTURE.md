# `vpnfs` Architecture & Specification

`vpnfs` is a native 9front (Plan 9) VPN client and file/network driver interface. It enables secure network tunneling over HTTPS/TLS protocols, starting with support for **Fortinet SSL-VPN**.

---

## 1. System Context & Environment (9front Native)

- **Compilation Toolchain:** 9front C compiler (`6c` / `6l` on amd64) and `mk` build utility.
- **Header Order:** Standard Plan 9 C order:
  ```c
  #include <u.h>
  #include <libc.h>
  #include "vpnfs.h"
  ```
- **TLS Infrastructure:** Plan 9 manages TLS in the kernel/network stack via `/net/tls`. Connections are initialized via `dial()` to obtain an IP socket, then upgraded using `pushtls()` or by opening `/net/tls/clone`.

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

## 3. Fortinet SSL-VPN Protocol Protocol Flow

```
[ vpnfs ]                              [ FortiGate Gateway ]
    |                                            |
    |--- TCP Dial & TLS Upgrade (port 443) ----->|
    |                                            |
    |--- HTTP POST /remote/logincheck ---------->|
    |    (username, credential, realm)           |
    |<-- HTTP 200 OK + SVPNCOOKIE ---------------|
    |                                            |
    |--- TCP Dial & TLS Upgrade (Tunnel) ------->|
    |--- HTTP GET /remote/sslvpn-tunnel -------->|
    |    (Cookie: SVPNCOOKIE=...)                |
    |                                            |
    |<====== 12-byte Encapsulated Binary =======>|
    |        IP/PPP Packet Stream                |
```

---

## 4. Fortinet 12-Byte Packet Framing Specification

When elevated to tunnel mode (`/remote/sslvpn-tunnel`), all IP/PPP packets exchanged over the TLS stream are encapsulated with a 12-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic 1 ('P' = 0x50)        |   Magic 2 ('A' = 0x41)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Total Frame Length (16-bit Big-Endian uint)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Control/Flags (0x01 = Data)   |       Reserved (0x00)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Reserved (0x00)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        IP / PPP Payload                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Framing Fields:
1. **Magic Bytes (0..1):** `0x50` (`'P'`), `0x41` (`'A'`).
2. **Total Frame Length (2..3):** Big-endian uint16 representing `12 + payload_len`.
3. **Flags / Reserved (4..11):** Control flag (e.g. `0x01` for data frame) followed by zeroed padding.

---

## 5. Plan 9 Network Integration

Packets received from the tunnel are un-framed and written to a Plan 9 `/pipe`. The pipe's endpoints interact with `ip/ppp` or `/net` stack drivers:

```
+---------------+     write_packet     +---------------+
|               |  ----------------->  |               |
| Plan 9 /pipe  |                      |    vpnfs      | ===> TLS Tunnel
|   (ip/ppp)    |  <-----------------  |               |
+---------------+      read_packet     +---------------+
```

---

## 6. Building `vpnfs`

On 9front (Plan 9):

```sh
# Compile vpnfs
mk

# Run vpnfs
vpnfs -v -h vpn.example.com -p 443 -u username -P password
```
