#include <u.h>
#include <libc.h>
#include "vpnfs.h"

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

	print("vpnfs: tunnel active. System pipe in: %d, out: %d\n", session.pipe_in, session.pipe_out);

	/* Fork process for bi-directional I/O:
	 * Parent: TLS -> Pipe Out
	 * Child:  Pipe In -> TLS
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
