/**
 *   6relayd - IPv6 relay daemon
 *   Copyright (C) 2012 Steven Barth <steven@midlink.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2
 *   as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 */

#pragma once
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <stdbool.h>
#include <syslog.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// RFC 6106 defines this router advertisement option
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

#define RELAYD_BUFFER_SIZE 1536
#define RELAYD_MAX_PREFIXES 8

#define _unused __attribute__((unused))


#define ALL_IPV6_NODES {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}}

#define ALL_IPV6_ROUTERS {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}}}


struct relayd_interface;

struct relayd_event {
	int socket;
	void (*handle_event)(struct relayd_event *event);
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct relayd_interface *iface);
};


struct relayd_interface {
	int ifindex;
	char ifname[IF_NAMESIZE];
	uint8_t mac[6];
	bool external;

	struct relayd_event timer_rs;
};


struct relayd_config {
	// Config
	bool enable_router_discovery_relay;
	bool enable_router_discovery_server;
	bool enable_forwarding;
	bool enable_dhcpv6_relay;
	bool enable_dhcpv6_server;
	bool enable_ndp_relay;
	bool enable_route_learning;

	bool force_address_assignment;
	bool send_router_solicitation;
	bool always_rewrite_dns;
	bool always_announce_default_router;
	bool deprecate_ula_if_public_avail;

	struct relayd_interface master;
	struct relayd_interface *slaves;
	size_t slavecount;

};


struct relayd_ipaddr {
	struct in6_addr addr;
	uint8_t prefix;
	uint32_t preferred;
	uint32_t valid;
};


// Exported main functions
int relayd_open_rtnl_socket(void);
int relayd_register_event(struct relayd_event *event);
ssize_t relayd_forward_packet(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct relayd_interface *iface);
ssize_t relayd_get_interface_addresses(int ifindex,
		struct relayd_ipaddr *addrs, size_t cnt);
int relayd_get_interface_mtu(const char *ifname);
struct relayd_interface* relayd_get_interface_by_index(int ifindex);
int relayd_sysctl_interface(const char *ifname, const char *option,
		const char *data);


// Exported module initializers
int init_router_discovery_relay(const struct relayd_config *relayd_config);
int init_dhcpv6_relay(const struct relayd_config *relayd_config);
int init_ndp_proxy(const struct relayd_config *relayd_config);

void deinit_router_discovery_relay(void);
void deinit_ndp_proxy();
