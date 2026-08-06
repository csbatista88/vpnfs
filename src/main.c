#include <u.h>
#include <libc.h>
#include "vpnfs.h"

typedef struct FortinetPriv FortinetPriv;
struct FortinetPriv {
	char ip[64];
	char dns1[64];
	char dns2[64];
	uchar txbuf[2 * VPN_BUFSIZE];
	int txlen;
};

VpnDriver *drivers[] = {
	&fortinet_driver,
	nil
};

VpnDriver*
vpn_driver_lookup(char *name)
{
	int i;

	for(i = 0; drivers[i] != nil; i++){
		if(cistrcmp(drivers[i]->name, name) == 0)
			return drivers[i];
	}
	return nil;
}

void
usage(void)
{
	fprint(2, "usage: vpnfs [-v] [-d driver] -h host [-p port] -u user -P pass [-r realm] [-t token]\n");
	exits("usage");
}

void
main(int argc, char *argv[])
{
	VpnConfig cfg;
	VpnSession session;
	VpnDriver *driver;
	char *driver_name;
	uchar buf[VPN_BUFSIZE];
	int n;

	memset(&cfg, 0, sizeof(cfg));
	memset(&session, 0, sizeof(session));
	driver_name = "fortinet";
	cfg.port = "443";

	ARGBEGIN {
	case 'd':
		driver_name = EARGF(usage());
		break;
	case 'h':
		cfg.host = EARGF(usage());
		break;
	case 'p':
		cfg.port = EARGF(usage());
		break;
	case 'u':
		cfg.user = EARGF(usage());
		break;
	case 'P':
		cfg.pass = EARGF(usage());
		break;
	case 'r':
		cfg.realm = EARGF(usage());
		break;
	case 't':
		cfg.token = EARGF(usage());
		break;
	case 'v':
		cfg.verbose = 1;
		break;
	default:
		usage();
	} ARGEND;

	if(cfg.host == nil || cfg.user == nil || cfg.pass == nil)
		usage();

	driver = vpn_driver_lookup(driver_name);
	if(driver == nil)
		sysfatal("unknown vpn driver: %s", driver_name);

	session.cfg = &cfg;
	session.driver = driver;
	session.tls_fd = -1;

	if(driver->init(&session) < 0)
		sysfatal("driver init failed");

	if(driver->auth(&session) < 0)
		sysfatal("authentication failed");

	if(vpn_create_pipes(&session) < 0)
		sysfatal("failed to create system pipes");

	if(driver->connect_tunnel(&session) < 0)
		sysfatal("tunnel connection failed");

	print("vpnfs: tunnel active. Communication pipes established (STDIN/STDOUT).\n");

	/* Automatically spawn /bin/ip/ppp daemon:
	 * STDIN (0)  = reads HDLC packets from p_to_ppp[0]
	 * STDOUT (1) = writes HDLC packets to p_from_ppp[1]
	 * STDERR (2) = redirected to /dev/null (shields RIO terminal window from rc -I)
	 * Flags: -P (Primary), -f (HDLC framing for pipes), -m 1400 (MTU)
	 */
	switch(rfork(RFPROC|RFFDG|RFNOTEG)){
	case -1:
		fprint(2, "vpnfs: warning: failed to fork ppp daemon: %r\n");
		break;
	case 0:
		dup(session.srv_out_fd, 0); /* STDIN  (0) = read packets from TLS (p_to_ppp[0]) */
		dup(session.srv_in_fd, 1);  /* STDOUT (1) = write packets to TLS (p_from_ppp[1]) */

		{
			int nullfd = open("/dev/null", ORDWR);
			if(nullfd >= 0){
				dup(nullfd, 2);     /* STDERR (2) = /dev/null (shields RIO terminal window) */
				close(nullfd);
			}
		}

		close(session.srv_out_fd);
		close(session.srv_in_fd);
		close(session.pipe_in);
		close(session.pipe_out);

		{
			FortinetPriv *priv = session.priv;
			char *iparg = (priv && priv->ip[0]) ? priv->ip : nil;

			if(cfg.verbose)
				print("vpnfs: starting /bin/ip/ppp -P -f -m 1400 %s...\n", iparg ? iparg : "");

			if(iparg != nil)
				execl("/bin/ip/ppp", "ppp", "-P", "-f", "-m", "1400", iparg, nil);
			else
				execl("/bin/ip/ppp", "ppp", "-P", "-f", "-m", "1400", nil);
		}
		fprint(2, "vpnfs: exec /bin/ip/ppp failed: %r\n");
		exits("exec ppp failed");
	}

	/* Close held descriptors in parent that were dup'd into child */
	close(session.srv_out_fd);
	close(session.srv_in_fd);

	/* Fork process for bi-directional I/O:
	 * Parent: TLS -> Pipe Out (p_to_ppp[1] -> STDIN of ip/ppp)
	 * Child:  Pipe In (p_from_ppp[0] <- STDOUT of ip/ppp) -> TLS
	 */
	switch(rfork(RFPROC|RFMEM)){
	case -1:
		sysfatal("rfork failed: %r");
	case 0:
		/* Child process: read packets from system pipe and write to TLS tunnel */
		while((n = read(session.pipe_in, buf, sizeof(buf))) > 0){
			if(driver->write_packet(&session, buf, n) < 0)
				break;
		}
		exits(nil);
	default:
		/* Parent process: read packets from TLS tunnel and write to system pipe */
		while((n = driver->read_packet(&session, buf, sizeof(buf))) >= 0){
			if(n == 0)
				continue; /* GFtype heartbeat / control packet skipped */
			if(write(session.pipe_out, buf, n) != n)
				break;
		}
		driver->close(&session);
		exits(nil);
	}
}
