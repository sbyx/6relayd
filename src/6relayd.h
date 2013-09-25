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

#pragma once
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <stdbool.h>
#include <syslog.h>

#ifdef WITH_UBUS

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#include "libubox/list.h"

#else

#include "list.h"

#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// RFC 6106 defines this router advertisement option
#define ND_OPT_ROUTE_INFO 24
#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNS_SEARCH 31

#define RELAYD_BUFFER_SIZE 8192
#define RELAYD_MAX_PREFIXES 8

#define _unused __attribute__((unused))
#define _packed __attribute__((packed))


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


struct relayd_ipaddr {
	struct in6_addr addr;
	uint8_t prefix;
	uint32_t preferred;
	uint32_t valid;
};

enum relayd_mode {
	RELAYD_DISABLED,
	RELAYD_SERVER,
	RELAYD_RELAY
};


struct relayd_interface {
	struct list_head head;

	int ifindex;
	char ifname[IF_NAMESIZE];

	// Runtime data
	struct relayd_event timer_rs;
	struct list_head ia_assignments;
	struct relayd_ipaddr ia_addr[8];
	size_t ia_addr_len;
	bool ia_reconf;

	// DHCPv4
	struct relayd_event dhcpv4_event;
	struct list_head dhcpv4_assignments;

	// Services
	enum relayd_mode ra;
	enum relayd_mode dhcpv6;
	enum relayd_mode ndp;
	enum relayd_mode dhcpv4;

	// Config
	bool external;
	bool master;
	bool always_rewrite_dns;
	bool deprecate_ula_if_public_avail;
	bool ra_not_onlink;

	int learn_routes;
	int default_router;
	int managed;
	int route_preference;

	// DHCPv4
	struct in_addr dhcpv4_start;
	struct in_addr dhcpv4_end;
	struct in_addr *dhcpv4_dns;
	size_t dhcpv4_dns_cnt;
	uint32_t dhcpv4_leasetime;
	char* dhcpv4_leases;
	size_t dhcpv4_lease_len;

	// DNS
	struct in6_addr *dns;
	size_t dns_cnt;
	uint8_t *search;
	size_t search_len;

	// Config
	char *dhcp_cb;
	char *dhcp_statefile;
	bool dhcp_state_done;

	char* dhcpv6_leases;
	size_t dhcpv6_lease_len;

	char* static_ndp;
	size_t static_ndp_len;
};

extern struct list_head interfaces;

#define RELAYD_MANAGED_MFLAG	1
#define RELAYD_MANAGED_NO_AFLAG	2


// Exported main functions
int relayd_open_rtnl_socket(void);
int relayd_register_event(struct relayd_event *event);

struct relayd_interface* relayd_open_interface(char* const argv[], int argc);
void relayd_close_interface(struct relayd_interface *iface);

ssize_t relayd_forward_packet(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct relayd_interface *iface);
ssize_t relayd_get_interface_addresses(int ifindex,
		struct relayd_ipaddr *addrs, size_t cnt);
struct relayd_interface* relayd_get_interface_by_name(const char *name);
int relayd_get_interface_mtu(const char *ifname);
int relayd_get_interface_mac(const char *ifname, uint8_t mac[6]);
struct relayd_interface* relayd_get_interface_by_index(int ifindex);
struct relayd_interface* relayd_get_master_interface(void);
void relayd_urandom(void *data, size_t len);
void relayd_setup_route(const struct in6_addr *addr, int prefixlen,
		const struct relayd_interface *iface, const struct in6_addr *gw, bool add);

struct relayd_interface* relayd_open_interface(char* const argv[], int argc);
void relayd_close_interface(struct relayd_interface *iface);

time_t relayd_monotonic_time(void);


// Exported module initializers
int init_router(void);
int init_dhcpv6(void);
int init_dhcpv4(void);
int init_ndp(void);
#ifdef WITH_UBUS
int init_ubus(void);
#endif

int setup_router_interface(struct relayd_interface *iface, bool enable);
int setup_dhcpv6_interface(struct relayd_interface *iface, bool enable);
int setup_ndp_interface(struct relayd_interface *iface, bool enable);
int setup_dhcpv4_interface(struct relayd_interface *iface, bool enable);
