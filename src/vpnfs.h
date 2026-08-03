#ifndef VPNFS_H
#define VPNFS_H

/* Fortinet framing header definitions */
#define FORTINET_HDR_MAGIC1  0x50 /* 'P' */
#define FORTINET_HDR_MAGIC2  0x41 /* 'A' */
#define FORTINET_HDR_LEN     12

/* Buffer size limits */
#define VPN_BUFSIZE          4096
#define VPN_COOKIE_LEN       512

typedef struct VpnConfig VpnConfig;
typedef struct VpnSession VpnSession;
typedef struct VpnDriver VpnDriver;

struct VpnConfig {
	char *host;
	char *port;
	char *user;
	char *pass;
	char *realm;
	char *token;
	int  verbose;
};

struct VpnSession {
	VpnConfig *cfg;
	VpnDriver *driver;
	int tls_fd;                 /* TLS data socket file descriptor */
	int pipe_in;                /* Pipe FD to read packets from system */
	int pipe_out;               /* Pipe FD to write packets to system */
	char cookie[VPN_COOKIE_LEN];/* Session cookie e.g., SVPNCOOKIE */
	void *priv;                 /* Driver private data pointer */
};

struct VpnDriver {
	char *name;
	int  (*init)(VpnSession *s);
	int  (*auth)(VpnSession *s);
	int  (*connect_tunnel)(VpnSession *s);
	int  (*read_packet)(VpnSession *s, uchar *buf, int maxlen);
	int  (*write_packet)(VpnSession *s, uchar *buf, int len);
	void (*close)(VpnSession *s);
};

/* Driver registration / retrieval */
VpnDriver *vpn_driver_lookup(char *name);

/* Network & TLS helper functions (src/net_plan9.c) */
int  vpn_dial(char *host, char *port);
int  vpn_pushtls(int fd, char *host);
int  vpn_http_post(int fd, char *host, char *path, char *body, char *resp, int maxresp);
int  vpn_http_get_tunnel(int fd, char *host, char *cookie);
int  vpn_create_pipes(VpnSession *s);

/* Driver declarations */
extern VpnDriver fortinet_driver;

#endif
