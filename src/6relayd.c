/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <resolv.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "6relayd.h"


struct list_head interfaces = LIST_HEAD_INIT(interfaces);
struct relayd_interface basecfg;

static int epoll, ioctl_sock;
static size_t epoll_registered = 0;
static volatile bool do_stop = false;

static int rtnl_socket = -1;
static int rtnl_seq = 0;
static int urandom_fd = -1;

static int print_usage(const char *name);
static void set_stop(_unused int signal);
static void wait_child(_unused int signal);
static void relayd_receive_packets(struct relayd_event *event);

static char *short_options = "ASR:D:NM::E::u:cn::l:a:rt:m:oi:p:dvh";
static struct option long_options[] = {
	{"relay", no_argument, NULL, 'A'},
	{"server", no_argument, NULL, 'S'},
	{"router-discovery", optional_argument, NULL, 'R'},
	{"dhcpv6", optional_argument, NULL, 'D'},
	{"ndp-proxy", no_argument, NULL, 'N'},
	{"master", optional_argument, NULL, 'M'},
	{"external", optional_argument, NULL, 'E'},
	{"override-default", optional_argument, NULL, 'u'},
	{"deprecate-ula", no_argument, NULL, 'c'},
	{"dns-server", optional_argument, NULL, 'n'},
	{"dns-search", required_argument, NULL, 's'},
	{"leasefile", required_argument, NULL, 'l'},
	{"lease", required_argument, NULL, 'a'},
	{"learn-routes", no_argument, NULL, 'r'},
	{"static-ndp", required_argument, NULL, 't'},
	{"managed", required_argument, NULL, 'm'},
	{"not-onlink", no_argument, NULL, 'o'},
	{"preference", required_argument, NULL, 'i'},
	{NULL, no_argument, NULL, 0}
};


int main(int argc, char* const argv[])
{
	memset(&basecfg, 0, sizeof(basecfg));
	const char *pidfile = "/var/run/6relayd.pid";
	bool daemonize = false;
	int verbosity = 0;
	int c;

	while ((c = getopt(argc, argv, short_options))) {
		switch (c) {
		case 'p':
			pidfile = optarg;
			break;

		case 'd':
			daemonize = true;
			break;

		case 'v':
			verbosity++;
			break;

		case '?':
			return print_usage(argv[0]);
		}
	}

	openlog("6relayd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	if (verbosity == 0)
		setlogmask(LOG_UPTO(LOG_WARNING));
	else if (verbosity == 1)
		setlogmask(LOG_UPTO(LOG_INFO));

	if (argc - optind < 1)
		return print_usage(argv[0]);

	if (getuid() != 0) {
		syslog(LOG_ERR, "Must be run as root. stopped.");
		return 2;
	}

	if ((epoll = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		syslog(LOG_ERR, "Unable to open epoll: %s", strerror(errno));
		return 2;
	}

	ioctl_sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if ((rtnl_socket = relayd_open_rtnl_socket()) < 0) {
		syslog(LOG_ERR, "Unable to open socket: %s", strerror(errno));
		return 2;
	}

	int paramc = optind;
	char* iargv[paramc + 2];
	memcpy(iargv, argv, sizeof(*iargv) * paramc);

	for (int i = 0; i < argc - paramc; ++i) {
		char *name = argv[paramc + i];
		bool external = (name[0] == '~');
		if (external)
			++name;

		if (name[0] == '.' && name[1] == 0)
			continue;

		iargv[0] = name;
		iargv[paramc] = (external) ? "-E1" : "-E0";
		iargv[paramc + 1] = (i == 0) ? "-M1" : "-M0";
		struct relayd_interface *iface = relayd_open_interface(iargv, paramc + 2);
		if (iface)
			return 3;
	}

	if ((urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0)
		return 4;

	signal(SIGUSR1, SIG_IGN);

	if (init_router())
		return 4;

	if (init_dhcpv6())
		return 4;

	if (init_ndp())
		return 4;

	if (epoll_registered == 0) {
		syslog(LOG_WARNING, "No relays enabled or no slave "
				"interfaces specified. stopped.");
		return 5;
	}

	if (daemonize) {
		openlog("6relayd", LOG_PID, LOG_DAEMON); // Disable LOG_PERROR
		if (daemon(0, 0)) {
			syslog(LOG_ERR, "Failed to daemonize: %s",
					strerror(errno));
			return 6;
		}
		FILE *fp = fopen(pidfile, "w");
		if (fp) {
			fprintf(fp, "%i\n", getpid());
			fclose(fp);
		}
	}

	signal(SIGTERM, set_stop);
	signal(SIGHUP, set_stop);
	signal(SIGINT, set_stop);
	signal(SIGCHLD, wait_child);

	// Main loop
	while (!do_stop) {
		struct epoll_event ev[16];
		int len = epoll_wait(epoll, ev, 16, -1);
		for (int i = 0; i < len; ++i) {
			struct relayd_event *event = ev[i].data.ptr;
			if (event->handle_event)
				event->handle_event(event);
			else if (event->handle_dgram)
				relayd_receive_packets(event);
		}
	}

	syslog(LOG_WARNING, "Termination requested by signal.");
	return 0;
}


static int print_usage(const char *name)
{
	fprintf(stderr,
	"Usage: %s [options] <master> [[~]<slave1> [[~]<slave2> [...]]]\n"
	"\nNote: to use server features only (no relaying) set master to '.'\n"
	"\nFeatures:\n"
	"	-A		Automatic relay (defaults: RrelayDrelayNsr)\n"
	"	-S		Automatic server (defaults: RserverDserver)\n"
	"	-R <mode>	Enable Router Discovery support (RD)\n"
	"	   relay	relay mode\n"
	"	   server	mini-server for Router Discovery on slaves\n"
	"	-D <mode>	Enable DHCPv6-support\n"
	"	   relay	standards-compliant relay\n"
	"	   server	server for DHCPv6 + PD on slaves\n"
	"	-N		Enable Neighbor Discovery Proxy (NDP)\n"
	"\nFeature options:\n"
	"	-u		RD: Assume default router even with ULA only\n"
	"	-c		RD: ULA-compatibility with broken devices\n"
	"	-m <mode>	RD: Address Management Level\n"
	"	   0 (default)	enable SLAAC and don't send Managed-Flag\n"
	"	   1		enable SLAAC and send Managed-Flag\n"
	"	   2		disable SLAAC and send Managed-Flag\n"
	"	-o		RD: Don't send on-link flag for prefixes\n"
	"	-i <preference>	RD: Route info and default preference\n"
	"	   medium	medium priority (default)\n"
	"	   low		low priority\n"
	"	   high		high priority\n"
	"	-n [server]	RD/DHCPv6: always rewrite name server\n"
	"	-l <file>,<cmd>	DHCPv6: IA lease-file and update callback\n"
	"	-a <duid>:<val>	DHCPv6: IA_NA static assignment\n"
	"	-r		NDP: learn routes to neighbors\n"
	"	-t <p>/<l>:<if>	NDP: define a static NDP-prefix on <if>\n"
	"	slave prefix ~	NDP: don't proxy NDP for hosts and only\n"
	"			serve NDP for DAD and traffic to router\n"
	"\nInvocation options:\n"
	"	-p <pidfile>	Set pidfile (/var/run/6relayd.pid)\n"
	"	-d		Daemonize\n"
	"	-v		Increase logging verbosity\n"
	"	-h		Show this help\n\n",
	name);
	return 1;
}


static void wait_child(_unused int signal)
{
	while (waitpid(-1, NULL, WNOHANG) > 0);
}


static void set_stop(_unused int signal)
{
	do_stop = true;
}

static int configure_interface(struct relayd_interface *iface, int argc, char* const argv[])
{
	optind = 1;
	int c, len;
	size_t optlen = strlen(optarg);
	size_t statelen;
	uint8_t buf[256];

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
		switch (c) {
		case 'A':
			iface->ra = RELAYD_RELAY;
			iface->dhcpv6 = RELAYD_RELAY;
			iface->ndp = RELAYD_RELAY;
			iface->learn_routes = true;
			break;

		case 'S':
			iface->ra = RELAYD_SERVER;
			iface->dhcpv6 = RELAYD_SERVER;
			break;

		case 'R':
			iface->ra = RELAYD_RELAY;
			if (!strcmp(optarg, "server"))
				iface->ra = RELAYD_SERVER;
			else if (strcmp(optarg, "relay"))
				return -1;
			break;

		case 'D':
			iface->dhcpv6 = RELAYD_RELAY;
			if (!strcmp(optarg, "server"))
				iface->dhcpv6 = RELAYD_SERVER;
			else if (strcmp(optarg, "relay"))
				return -1;
			break;

		case 'N':
			iface->ndp = true;
			break;

		case 'M':
			iface->master = true;
			if (optarg)
				iface->master = !!atoi(optarg);
			break;

		case 'E':
			iface->external = true;
			if (optarg)
				iface->external = !!atoi(optarg);
			break;

		case 'u':
			iface->default_router = (optarg) ? atoi(optarg) : 1;
			break;

		case 'c':
			iface->deprecate_ula_if_public_avail = true;
			break;

		case 'n':
			iface->always_rewrite_dns = true;
			if (optarg) {
				iface->dns = realloc(iface->dns,
						++iface->dns_cnt * sizeof(*iface->dns));
				inet_pton(AF_INET6, optarg, &iface->dns[iface->dns_cnt - 1]);
			}
			break;

		case 's':
			len = dn_comp(optarg, buf, sizeof(buf), NULL, NULL);
			if (len <= 0)
				return -1;

			iface->search = realloc(iface->search, iface->search_len + len);
			memcpy(iface->search + iface->search_len, buf, len);
			iface->search_len += len;
			break;

		case 'l':
			statelen = strcspn(optarg, ",");
			iface->dhcpv6_statefile = strndup(optarg, statelen);
			if (optlen > statelen)
				iface->dhcpv6_cb = strdup(&optarg[statelen + 1]);
			break;

		case 'a':
			iface->dhcpv6_leases = realloc(iface->dhcpv6_leases,
					iface->dhcpv6_lease_len + optlen + 2);
			memcpy(iface->dhcpv6_leases + iface->dhcpv6_lease_len, optarg, optlen);
			iface->dhcpv6_lease_len += optlen + 2;
			iface->dhcpv6_leases[iface->dhcpv6_lease_len - 2] = ' ';
			iface->dhcpv6_leases[iface->dhcpv6_lease_len - 1] = 0;
			break;

		case 'r':
			iface->learn_routes = true;
			break;

		case 't':
			iface->static_ndp = realloc(iface->static_ndp,
					iface->static_ndp_len + optlen + 2);
			memcpy(iface->static_ndp + iface->static_ndp_len, optarg, optlen);
			iface->static_ndp_len += optlen + 2;
			iface->static_ndp[iface->static_ndp_len - 2] = ' ';
			iface->static_ndp[iface->static_ndp_len - 1] = 0;
			break;

		case 'm':
			iface->managed = atoi(optarg);
			break;

		case 'o':
			iface->ra_not_onlink = true;
			break;

		case 'i':
			if (!strcmp(optarg, "low"))
				iface->route_preference = -1;
			else if (!strcmp(optarg, "high"))
				iface->route_preference = 1;
			break;

		case '?':
			return -1;
		}
	}

	return 0;
}


// Create an interface context
struct relayd_interface* relayd_open_interface(char* const argv[], int argc)
{
	const char *ifname = argv[0];
	struct relayd_interface *iface = relayd_get_interface_by_name(ifname);
	if (!iface) {
		size_t ifname_len = strlen(ifname) + 1;
		if (ifname_len > IF_NAMESIZE)
			ifname_len = IF_NAMESIZE;

		struct ifreq ifr;
		memcpy(ifr.ifr_name, ifname, ifname_len);

		// Detect interface index
		if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr) < 0) {
			syslog(LOG_ERR, "Unable to open interface %s (%s)",
						ifname, strerror(errno));
			return NULL;
		}

		iface = malloc(sizeof(*iface));
		*iface = basecfg;

		// Copy allocated buffers
		if (iface->dns) {
			iface->dns = malloc(iface->dns_cnt);
			memcpy(iface->dns, basecfg.dns, iface->dns_cnt);
		}

		if (iface->search) {
			iface->search = malloc(iface->search_len);
			memcpy(iface->search, basecfg.search, iface->dns_cnt);
		}

		if (iface->dhcpv6_cb)
			iface->dhcpv6_cb = strdup(iface->dhcpv6_cb);

		if (iface->dhcpv6_statefile)
			iface->dhcpv6_statefile = strdup(iface->dhcpv6_statefile);

		if (iface->dhcpv6_leases)
			iface->dhcpv6_leases = strdup(iface->dhcpv6_leases);

		if (iface->static_ndp)
			iface->static_ndp = strdup(iface->static_ndp);

		// Fill interface structure
		iface->ifindex = ifr.ifr_ifindex;
		memcpy(iface->ifname, ifname, ifname_len);
	}

	struct relayd_interface *master = relayd_get_master_interface();
	if (configure_interface(iface, argc, argv)) {
		relayd_close_interface(iface);
		return NULL;
	}

	setup_router_interface(iface, true);
	setup_dhcpv6_interface(iface, true);
	setup_ndp_interface(iface, true);

	if ((master != iface) && iface->master)
		relayd_close_interface(master);

	list_add_tail(&iface->head, &interfaces);
	return iface;
}


void relayd_close_interface(struct relayd_interface *iface)
{
	if (iface->head.next)
		list_del(&iface->head);

	setup_router_interface(iface, false);
	setup_dhcpv6_interface(iface, false);
	setup_ndp_interface(iface, false);

	free(iface->dns);
	free(iface->search);
	free(iface->dhcpv6_cb);
	free(iface->dhcpv6_statefile);
	free(iface->dhcpv6_leases);
	free(iface->static_ndp);
	free(iface);
}


int relayd_open_rtnl_socket(void)
{
	int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

	// Connect to the kernel netlink interface
	struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
	if (connect(sock, (struct sockaddr*)&nl, sizeof(nl))) {
		syslog(LOG_ERR, "Failed to connect to kernel rtnetlink: %s",
				strerror(errno));
		return -1;
	}

	return sock;
}


// Read IPv6 MTU for interface
int relayd_get_interface_mtu(const char *ifname)
{
	char buf[64];
	const char *sysctl_pattern = "/proc/sys/net/ipv6/conf/%s/mtu";
	snprintf(buf, sizeof(buf), sysctl_pattern, ifname);

	int fd = open(buf, O_RDONLY);
	ssize_t len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len < 0)
		return -1;


	buf[len] = 0;
	return atoi(buf);

}


// Read IPv6 MAC for interface
int relayd_get_interface_mac(const char *ifname, uint8_t mac[6])
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}


// Register events for the multiplexer
int relayd_register_event(struct relayd_event *event)
{
	struct epoll_event ev = {EPOLLIN | EPOLLET, {event}};
	if (!epoll_ctl(epoll, EPOLL_CTL_ADD, event->socket, &ev)) {
		++epoll_registered;
		return 0;
	} else {
		return -1;
	}
}


// Forwards a packet on a specific interface
ssize_t relayd_forward_packet(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct relayd_interface *iface)
{
	// Construct headers
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	struct msghdr msg = {(void*)dest, sizeof(*dest), iov, iov_len,
				cmsg_buf, sizeof(cmsg_buf), 0};

	// Set control data (define destination interface)
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(chdr);
	pktinfo->ipi6_ifindex = iface->ifindex;

	// Also set scope ID if link-local
	if (IN6_IS_ADDR_LINKLOCAL(&dest->sin6_addr)
			|| IN6_IS_ADDR_MC_LINKLOCAL(&dest->sin6_addr))
		dest->sin6_scope_id = iface->ifindex;

	// IPV6_PKTINFO doesn't really work for IPv6-raw sockets (bug?)
	if (dest->sin6_port == 0) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dest->sin6_addr, ipbuf, sizeof(ipbuf));

	ssize_t sent = sendmsg(socket, &msg, MSG_DONTWAIT);
	if (sent < 0)
		syslog(LOG_WARNING, "Failed to relay to %s%%%s (%s)",
				ipbuf, iface->ifname, strerror(errno));
	else
		syslog(LOG_NOTICE, "Relayed %li bytes to %s%%%s",
				(long)sent, ipbuf, iface->ifname);
	return sent;
}


// Detect an IPV6-address currently assigned to the given interface
ssize_t relayd_get_interface_addresses(int ifindex,
		struct relayd_ipaddr *addrs, size_t cnt)
{
	struct {
		struct nlmsghdr nhm;
		struct ifaddrmsg ifa;
	} req = {{sizeof(req), RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP,
			++rtnl_seq, 0}, {AF_INET6, 0, 0, 0, ifindex}};
	if (send(rtnl_socket, &req, sizeof(req), 0) < (ssize_t)sizeof(req))
		return 0;

	uint8_t buf[8192];
	ssize_t len = 0, ret = 0;

	for (struct nlmsghdr *nhm = NULL; ; nhm = NLMSG_NEXT(nhm, len)) {
		while (len < 0 || !NLMSG_OK(nhm, (size_t)len)) {
			len = recv(rtnl_socket, buf, sizeof(buf), 0);
			nhm = (struct nlmsghdr*)buf;
			if (len < 0 || !NLMSG_OK(nhm, (size_t)len)) {
				if (errno == EINTR)
					continue;
				else
					return ret;
			}
		}

		if (nhm->nlmsg_type != RTM_NEWADDR)
			break;

		// Skip address but keep clearing socket buffer
		if (ret >= (ssize_t)cnt)
			continue;

		struct ifaddrmsg *ifa = NLMSG_DATA(nhm);
		if (ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
				ifa->ifa_index != (unsigned)ifindex)
			continue;

		struct rtattr *rta = (struct rtattr*)&ifa[1];
		size_t alen = NLMSG_PAYLOAD(nhm, sizeof(*ifa));
		memset(&addrs[ret], 0, sizeof(addrs[ret]));
		addrs[ret].prefix = ifa->ifa_prefixlen;

		while (RTA_OK(rta, alen)) {
			if (rta->rta_type == IFA_ADDRESS) {
				memcpy(&addrs[ret].addr, RTA_DATA(rta),
						sizeof(struct in6_addr));
			} else if (rta->rta_type == IFA_CACHEINFO) {
				struct ifa_cacheinfo *ifc = RTA_DATA(rta);
				addrs[ret].preferred = ifc->ifa_prefered;
				addrs[ret].valid = ifc->ifa_valid;
			}

			rta = RTA_NEXT(rta, alen);
		}

		if (ifa->ifa_flags & IFA_F_DEPRECATED)
			addrs[ret].preferred = 0;

		++ret;
	}

	return ret;
}


struct relayd_interface* relayd_get_interface_by_index(int ifindex)
{
	struct relayd_interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (iface->ifindex == ifindex)
			return iface;

	return NULL;
}


struct relayd_interface* relayd_get_interface_by_name(const char *name)
{
	struct relayd_interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (!strcmp(iface->ifname, name))
			return iface;

	return NULL;
}


struct relayd_interface* relayd_get_master_interface(void)
{
	struct relayd_interface *iface;
	list_for_each_entry(iface, &interfaces, head)
		if (iface->master)
			return iface;

	return NULL;
}


// Convenience function to receive and do basic validation of packets
static void relayd_receive_packets(struct relayd_event *event)
{
	uint8_t data_buf[RELAYD_BUFFER_SIZE], cmsg_buf[128];
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_ll ll;
		struct sockaddr_nl nl;
	} addr;

	while (true) {
		struct iovec iov = {data_buf, sizeof(data_buf)};
		struct msghdr msg = {&addr, sizeof(addr), &iov, 1,
				cmsg_buf, sizeof(cmsg_buf), 0};

		ssize_t len = recvmsg(event->socket, &msg, MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN)
				break;
			else
				continue;
		}


		// Extract destination interface
		int destiface = 0;
		struct in6_pktinfo *pktinfo;
		for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch != NULL &&
				destiface == 0; ch = CMSG_NXTHDR(&msg, ch)) {
			if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_PKTINFO) {
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(ch);
				destiface = pktinfo->ipi6_ifindex;
			}
		}

		// Detect interface for packet sockets
		if (addr.ll.sll_family == AF_PACKET)
			destiface = addr.ll.sll_ifindex;

		struct relayd_interface *iface =
				relayd_get_interface_by_index(destiface);

		if (!iface && addr.nl.nl_family != AF_NETLINK)
			continue;

		char ipbuf[INET6_ADDRSTRLEN] = "kernel";
		if (addr.ll.sll_family == AF_PACKET &&
				len >= (ssize_t)sizeof(struct ip6_hdr))
			inet_ntop(AF_INET6, &data_buf[8], ipbuf, sizeof(ipbuf));
		else if (addr.in6.sin6_family == AF_INET6)
			inet_ntop(AF_INET6, &addr.in6.sin6_addr, ipbuf, sizeof(ipbuf));

		syslog(LOG_NOTICE, "--");
		syslog(LOG_NOTICE, "Received %li Bytes from %s%%%s", (long)len,
				ipbuf, (iface) ? iface->ifname : "netlink");

		event->handle_dgram(&addr, data_buf, len, iface);
	}
}


void relayd_urandom(void *data, size_t len)
{
	read(urandom_fd, data, len);
}
