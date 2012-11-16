/**
 * Copyright (C) 2012 Steven Barth <steven@midlink.org>
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
 * with parts taken from dnsmasq, Copyright 2000-2012 Simon Kelley
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <sys/timerfd.h>

#include "list.h"
#include "router.h"
#include "6relayd.h"


static void forward_router_solicitation(const struct relayd_interface *iface);
static void forward_router_advertisement(uint8_t *data, size_t len);
static int open_icmpv6_socket(struct icmp6_filter *filt,
		struct ipv6_mreq *slave_mreq);

static void handle_icmpv6(void *addr, void *data, size_t len,
		struct relayd_interface *iface);
static void send_router_advert(struct relayd_event *event);

static struct relayd_event router_discovery_event = {-1, NULL, handle_icmpv6};

static const struct relayd_config *config = NULL;



int init_router_discovery_relay(const struct relayd_config *relayd_config)
{
	config = relayd_config;

	// Filter ICMPv6 package types
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filt);

	// Open ICMPv6 socket
	struct ipv6_mreq slaves = {ALL_IPV6_ROUTERS, config->master.ifindex};
	router_discovery_event.socket = open_icmpv6_socket(&filt, &slaves);

	if (router_discovery_event.socket < 0) {
		syslog(LOG_ERR, "Failed to open RAW-socket: %s",
				strerror(errno));
		return -1;
	}

	if (config->enable_router_discovery_server) {
		for (size_t i = 0; i < config->slavecount; ++i) {
			struct relayd_interface *iface = &config->slaves[i];
			iface->timer_rs.socket = timerfd_create(CLOCK_MONOTONIC,
					TFD_CLOEXEC | TFD_NONBLOCK);
			iface->timer_rs.handle_event = send_router_advert;
			relayd_register_event(&iface->timer_rs);
			send_router_advert(&iface->timer_rs);
		}
	} else if (config->enable_router_discovery_relay) {
		struct ipv6_mreq an = {ALL_IPV6_NODES, config->master.ifindex};
		setsockopt(router_discovery_event.socket, IPPROTO_IPV6,
				IPV6_ADD_MEMBERSHIP, &an, sizeof(an));
	}

	if (config->send_router_solicitation)
		forward_router_solicitation(&config->master);

	if (config->slavecount > 0 && (config->enable_router_discovery_relay ||
			config->enable_router_discovery_server))
		relayd_register_event(&router_discovery_event);
	else
		close(router_discovery_event.socket);

	return 0;
}


// Create an ICMPv6 socket and setup basic attributes
static int open_icmpv6_socket(struct icmp6_filter *filt, struct ipv6_mreq *slave_mreq)
{
	int sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sock < 0)
		return -1;

	// Let the kernel compute our checksums
	int val = 2;
	setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	// We need to know the source interface
	val = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));

	// Filter ICMPv6 package types
	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, filt, sizeof(*filt));

	// Configure multicast addresses
	for (size_t i = 0; i < config->slavecount; ++i) {
		slave_mreq->ipv6mr_interface = config->slaves[i].ifindex;
		setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				slave_mreq, sizeof(*slave_mreq));
	}

	return sock;
}


// Event handler for incoming ICMPv6 packets
static void handle_icmpv6(_unused void *addr, void *data, size_t len,
		struct relayd_interface *iface)
{
	struct icmp6_hdr *hdr = data;
	if (config->enable_router_discovery_server) { // Server mode
		if (hdr->icmp6_type == ND_ROUTER_SOLICIT &&
				iface != &config->master)
			send_router_advert(&iface->timer_rs);
	} else { // Relay mode
		if (hdr->icmp6_type == ND_ROUTER_ADVERT
				&& iface == &config->master)
			forward_router_advertisement(data, len);
		else if (hdr->icmp6_type == ND_ROUTER_SOLICIT
				&& iface != &config->master)
			forward_router_solicitation(&config->master);
	}
}


// Router Advert server mode
static void send_router_advert(struct relayd_event *event)
{
	uint64_t overrun;
	read(event->socket, &overrun, sizeof(overrun));
	struct relayd_interface *iface =
			container_of(event, struct relayd_interface, timer_rs);

	struct {
		struct nd_router_advert h;
		struct icmpv6_opt lladdr;
		struct nd_opt_mtu mtu;
		//struct icmpv6_opt rdnss;
		//struct in6_addr rdnss_addr;
		struct nd_opt_prefix_info prefix[4];
	} adv = {
		.h = {{.icmp6_type = ND_ROUTER_ADVERT, .icmp6_code = 0}, 0, 0},
		.lladdr = {ND_OPT_SOURCE_LINKADDR, 1, {0}},
		.mtu = {ND_OPT_MTU, 1, 0, htonl(iface->mtu)},
		//.rdnss = {ND_OPT_RECURSIVE_DNS, 3, {0, 0, 255, 255, 255, 255}},
	};
	adv.h.nd_ra_flags_reserved = ND_RA_FLAG_OTHER;
	adv.h.nd_ra_router_lifetime = htons(3 * MaxRtrAdvInterval);
	memcpy(adv.lladdr.data, iface->mac, sizeof(adv.lladdr.data));

	struct ifaddrs *ifaddrs;
	if (getifaddrs(&ifaddrs))
		return;

	size_t cnt = 0; // Construct Prefix Information options
	for (struct ifaddrs *c = ifaddrs; c; c = c->ifa_next) {
		if (cnt >= ARRAY_SIZE(adv.prefix))
			break;
		else if (!c->ifa_addr || strcmp(c->ifa_name, iface->ifname) ||
				c->ifa_addr->sa_family != AF_INET6)
			continue;

		struct sockaddr_in6 *addr = (struct sockaddr_in6*)c->ifa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr))
			continue;

		//if (cnt == 0)
		//	adv.rdnss_addr = addr->sin6_addr;

		bool already_announced = false;
		for (size_t i = 0; i < cnt; ++i)
			if (!memcmp(&adv.prefix[i].nd_opt_pi_prefix,
					&addr->sin6_addr, 8))
				already_announced = true;

		if (already_announced)
			continue;

		adv.prefix[cnt].nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		adv.prefix[cnt].nd_opt_pi_len = 4;
		adv.prefix[cnt].nd_opt_pi_prefix_len = 64;
		adv.prefix[cnt].nd_opt_pi_flags_reserved =
				ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
		adv.prefix[cnt].nd_opt_pi_valid_time =
				htonl(3 * MaxRtrAdvInterval);
		adv.prefix[cnt].nd_opt_pi_preferred_time =
				htonl(2 * MaxRtrAdvInterval);
		memcpy(&adv.prefix[cnt].nd_opt_pi_prefix,
				&addr->sin6_addr, 8);
		++cnt;
	}

	freeifaddrs(ifaddrs);

	struct iovec iov = {&adv, (uint8_t*)&adv.prefix[cnt] - (uint8_t*)&adv};
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	relayd_forward_packet(router_discovery_event.socket,
			&all_nodes, &iov, 1, iface);


	// Rearm timer
	struct itimerspec val = {{0,0}, {0,0}};
	val.it_value.tv_sec = (random() % (MaxRtrAdvInterval
			- MinRtrAdvInterval)) + MinRtrAdvInterval;
	timerfd_settime(event->socket, 0, &val, NULL);
}


// Forward router solicitation
static void forward_router_solicitation(const struct relayd_interface *iface)
{
	struct icmp6_hdr rs = {ND_ROUTER_SOLICIT, 0, 0, {{0}}};
	struct iovec iov = {&rs, sizeof(rs)};
	struct sockaddr_in6 all_routers =
		{AF_INET6, 0, 0, ALL_IPV6_ROUTERS, iface->ifindex};

	if (config->force_address_assignment) {
		relayd_sysctl_interface(config->master.ifname,
				"accept_ra", "2");

		for (size_t i = 0; i < config->slavecount; ++i)
			relayd_sysctl_interface(config->slaves[i].ifname,
					"accept_ra", "2");
	}

	syslog(LOG_NOTICE, "Sending RS to %s", iface->ifname);
	relayd_forward_packet(router_discovery_event.socket,
			&all_routers, &iov, 1, iface);
}


// Handler for incoming router solicitations on slave interfaces
static void forward_router_advertisement(uint8_t *data, size_t len)
{
	struct nd_router_advert *adv = (struct nd_router_advert *)data;

	// Rewrite options
	uint8_t *end = data + len;
	uint8_t *mac_ptr = NULL;
	bool rewrite_dns = false;
	struct in6_addr *dns_ptr = NULL;
	size_t dns_count = 0;

	struct icmpv6_opt *opt;
	icmpv6_for_each_option(opt, &adv[1], end) {
		if (opt->type == ND_OPT_SOURCE_LINKADDR) {
			// Store address of source MAC-address
			mac_ptr = opt->data;
		} else if (opt->type == ND_OPT_RECURSIVE_DNS && opt->len > 1) {
			// Check if we have to rewrite DNS
			rewrite_dns = config->always_rewrite_dns;
			dns_ptr = (struct in6_addr*)&opt->data[6];
			dns_count = (opt->len - 1) / 2;

			// If there is a link-local DNS we must rewrite
			for (size_t i = 0; !rewrite_dns && i < dns_count; ++i)
				if (IN6_IS_ADDR_LINKLOCAL(&dns_ptr[i]))
					rewrite_dns = true;
		}
	}

	syslog(LOG_NOTICE, "Got a RA");

	if (config->enable_dhcpv6_server) // Announce stateless DHCP
		adv->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;

	// Indicate a proxy, however we don't follow the rest of RFC 4389 yet
	adv->nd_ra_flags_reserved |= ND_RA_FLAG_PROXY;

	// Forward advertisement to all slave interfaces
	struct sockaddr_in6 all_nodes = {AF_INET6, 0, 0, ALL_IPV6_NODES, 0};
	struct iovec iov = {data, len};
	for (size_t i = 0; i < config->slavecount; ++i) {
		// Fixup source hardware address option
		if (mac_ptr)
			memcpy(mac_ptr, config->slaves[i].mac, 6);

		// If we have to rewrite DNS entries
		if (rewrite_dns && dns_ptr && dns_count > 0) {
			if (relayd_get_interface_address(&dns_ptr[0],
					config->slaves[i].ifname, true))
				continue; // Unable to comply

			// Copy over any other addresses
			for (size_t i = 1; i < dns_count; ++i)
				memcpy(&dns_ptr[i], &dns_ptr[0],
						sizeof(struct in6_addr));
		}

		relayd_forward_packet(router_discovery_event.socket,
			&all_nodes, &iov, 1, &config->slaves[i]);
	}
}
