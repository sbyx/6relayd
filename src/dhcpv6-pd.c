/**
 * Copyright (C) 2013 Steven Barth <steven@midlink.org>
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

#include "list.h"
#include "6relayd.h"
#include "dhcpv6.h"
#include "md5.h"

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>


struct assignment {
	struct list_head head;
	struct sockaddr_in6 peer;
	time_t valid_until;
	time_t reconf_sent;
	int reconf_cnt;
	uint8_t key[16];
	uint32_t assigned;
	uint32_t iaid;
	uint8_t length;
	uint8_t clid_len;
	uint8_t clid_data[];
};


static const struct relayd_config *config = NULL;
static void reconf_timer(struct relayd_event *event);
static struct relayd_event reconf_event = {-1, reconf_timer, NULL};
static int socket_fd = -1;
static uint32_t serial = 0;



int dhcpv6_init_pd(const struct relayd_config *relayd_config, int dhcpv6_socket)
{
	config = relayd_config;
	socket_fd = dhcpv6_socket;

	reconf_event.socket = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (reconf_event.socket < 0) {
		syslog(LOG_ERR, "Failed to create timer: %s", strerror(errno));
		return -1;
	}

	relayd_register_event(&reconf_event);

	struct itimerspec its = {{2, 0}, {2, 0}};
	timerfd_settime(reconf_event.socket, 0, &its, NULL);

	return 0;
}


static time_t monotonic_time(void)
{
	struct timespec ts;
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}


static int send_reconf(struct relayd_interface *iface, struct assignment *assign)
{
	struct {
		struct dhcpv6_client_header hdr;
		uint16_t srvid_type;
		uint16_t srvid_len;
		uint16_t duid_type;
		uint16_t hardware_type;
		uint8_t mac[6];
		uint16_t msg_type;
		uint16_t msg_len;
		uint8_t msg_id;
		struct dhcpv6_auth_reconfigure auth;
		uint16_t clid_type;
		uint16_t clid_len;
		uint8_t clid_data[128];
	} __attribute__((packed)) reconf_msg = {
		.hdr = {DHCPV6_MSG_RECONFIGURE, {0, 0, 0}},
		.srvid_type = htons(DHCPV6_OPT_SERVERID),
		.srvid_len = htons(10),
		.duid_type = htons(3),
		.hardware_type = htons(1),
		.mac = {iface->mac[0], iface->mac[1], iface->mac[2],
				iface->mac[3], iface->mac[4], iface->mac[5]},
		.msg_type = htons(DHCPV6_OPT_RECONF_MSG),
		.msg_len = htons(1),
		.msg_id = DHCPV6_MSG_RENEW,
		.auth = {htons(DHCPV6_OPT_AUTH),
				htons(sizeof(reconf_msg.auth) - 4), 3, 1, 0,
				{htonl(time(NULL)), htonl(++serial)}, 2, {0}},
		.clid_type = htons(DHCPV6_OPT_CLIENTID),
		.clid_len = htons(assign->clid_len),
		.clid_data = {0},
	};
	memcpy(reconf_msg.clid_data, assign->clid_data, assign->clid_len);
	struct iovec iov = {&reconf_msg, sizeof(reconf_msg) + assign->clid_len};

	md5_state_t md5;
	uint8_t secretbytes[16];
	memcpy(secretbytes, assign->key, sizeof(secretbytes));

	for (size_t i = 0; i < sizeof(secretbytes); ++i)
		secretbytes[i] ^= 0x36;

	md5_init(&md5);
	md5_append(&md5, secretbytes, sizeof(secretbytes));
	md5_append(&md5, iov.iov_base, iov.iov_len);
	md5_finish(&md5, reconf_msg.auth.key);

	for (size_t i = 0; i < sizeof(secretbytes); ++i) {
		secretbytes[i] ^= 0x36;
		secretbytes[i] ^= 0x5c;
	}

	md5_init(&md5);
	md5_append(&md5, secretbytes, sizeof(secretbytes));
	md5_append(&md5, reconf_msg.auth.key, 16);
	md5_finish(&md5, reconf_msg.auth.key);

	return relayd_forward_packet(socket_fd, &assign->peer, &iov, 1, iface);
}


static void reconf_timer(struct relayd_event *event)
{
	uint64_t cnt;
	if (read(event->socket, &cnt, sizeof(cnt))) {
		// Avoid compiler warning
	}

	time_t now = monotonic_time();
	for (size_t i = 0; i < config->slavecount; ++i) {
		struct relayd_interface *iface = &config->slaves[i];
		struct assignment *a, *n;
		list_for_each_entry_safe(a, n, &iface->pd_assignments, head) {
			if (a->valid_until > now) {
				list_del(&a->head);
				free(a);
			} else if (a->reconf_cnt > 0 && a->reconf_cnt < 8 &&
					now > a->reconf_sent + (1 << a->reconf_cnt)) {
				++a->reconf_cnt;
				a->reconf_sent = now;
				send_reconf(iface, a);
			}
		}
	}
}


static struct assignment* find(struct relayd_interface *iface, const void *clid_data,
		size_t clid_len, uint32_t iaid)
{
	struct assignment *c;
	list_for_each_entry(c, &iface->pd_assignments, head)
		if (c->clid_len == clid_len && c->iaid == iaid &&
				!memcmp(c->clid_data, clid_data, clid_len))
			return c;
	return NULL;
}


static bool assign(struct relayd_interface *iface, struct assignment *assign)
{
	struct assignment *c;

	// Try honoring the hint first
	uint32_t current = 1, asize = (1 << (64 - assign->length)) - 1;
	if (assign->assigned) {
		list_for_each_entry(c, &iface->pd_assignments, head) {
			if (assign->assigned > current && assign->assigned + asize < c->assigned) {
				list_add_tail(&assign->head, &c->head);
				return true;
			}

			if (c->assigned != 0)
				current = (c->assigned + (1 << (64 - c->length)));
		}
	}

	// Fallback to a variable assignment
	list_for_each_entry(c, &iface->pd_assignments, head) {
		current = (current + asize) & (~asize);
		if (current + asize < c->assigned) {
			assign->assigned = current;
			list_add_tail(&assign->head, &c->head);
			return true;
		}

		if (c->assigned != 0)
			current = (c->assigned + (1 << (64 - c->length)));
	}

	return false;
}


static void update(struct relayd_interface *iface)
{
	int min_prefix_len = -1;

	if (iface->pd_assignments.next == NULL) {
		INIT_LIST_HEAD(&iface->pd_assignments);
		struct assignment *border = calloc(1, sizeof(*border));
		border->length = 64;
		list_add(&border->head, &iface->pd_assignments);
	}

	struct relayd_ipaddr addr[8];
	int len = relayd_get_interface_addresses(iface->ifindex, addr, 8);

	if (len < 0)
		return;

	time_t now = monotonic_time();
	int minprefix = -1;

	for (int i = 0; i < len; ++i) {
		if (addr[i].prefix > minprefix)
			minprefix = addr[i].prefix;

		addr[i].preferred += now;
		addr[i].valid += now;
	}

	struct assignment *border = list_last_entry(&iface->pd_assignments, struct assignment, head);
	border->assigned = 1 << (64 - min_prefix_len);

	bool change = len != (int)iface->pd_addr_len
			|| memcmp(iface->pd_addr, addr, len * sizeof(*border));

	memcpy(iface->pd_addr, addr, len * sizeof(*border));
	iface->pd_addr_len = len;

	if (change) {
		struct list_head reassign = LIST_HEAD_INIT(reassign);
		struct assignment *c, *d;
		list_for_each_entry_safe(c, d, &iface->pd_assignments, head) {
			c->reconf_sent = now;
			c->reconf_cnt = 1;

			if (c->assigned >= border->assigned)
				list_move(&c->head, &reassign);

			send_reconf(iface, c);
		}

		while (!list_empty(&reassign)) {
			c = list_first_entry(&reassign, struct assignment, head);
			list_del(&c->head);
			if (!assign(iface, c)) {
				c->assigned = 0;
				list_add(&c->head, &iface->pd_assignments);
			}
		}
	}
}


static size_t append_reply(uint8_t *buf, size_t buflen, uint16_t status,
		const struct dhcpv6_ia_hdr *ia, struct assignment *a,
		struct relayd_interface *iface)
{
	if (buflen < sizeof(*ia) + sizeof(struct dhcpv6_ia_prefix))
		return 0;

	struct dhcpv6_ia_hdr out = {htons(DHCPV6_OPT_IA_PD), 0, ia->iaid, 0, 0};
	size_t datalen = sizeof(out);

	if (status) {
		struct __attribute__((packed)) {
			uint16_t type;
			uint16_t len;
			uint16_t value;
		} stat = {htons(DHCPV6_OPT_STATUS), htons(sizeof(stat) - 4),
				htons(status)};

		memcpy(buf + datalen, &stat, sizeof(stat));
		datalen += sizeof(stat);
	} else {
		uint32_t pref = 86400;
		uint32_t valid = 86400;

		for (size_t i = 0; i < iface->pd_addr_len; ++i) {
			struct dhcpv6_ia_prefix p = {
				.type = htons(DHCPV6_OPT_IA_PREFIX),
				.len = htons(sizeof(p) - 4),
				.preferred = htonl(iface->pd_addr[i].preferred),
				.valid = htonl(iface->pd_addr[i].valid),
				.prefix = a->length,
				.addr = iface->pd_addr[i].addr
			};
			p.addr.s6_addr32[1] |= htonl(a->assigned);

			if (datalen + sizeof(p) > buflen)
				continue;

			if (iface->pd_addr[i].preferred < pref &&
					iface->pd_addr[i].preferred > 7200)
				pref = iface->pd_addr[i].preferred;

			if (iface->pd_addr[i].valid < valid &&
					iface->pd_addr[i].valid > 7200)
				valid = iface->pd_addr[i].valid;

			memcpy(buf + datalen, &p, sizeof(p));
			datalen += sizeof(p);
		}

		a->valid_until = valid;
		out.t1 = htonl(pref * 5 / 10);
		out.t2 = htonl(pref * 8 / 10);
	}

	out.len = htons(datalen - 4);
	memcpy(buf, &out, sizeof(out));
	return datalen;
}


size_t dhcpv6_handle_pd(uint8_t *buf, size_t buflen, struct relayd_interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end)
{
	size_t response_len = 0;
	const struct dhcpv6_client_header *hdr = data;
	uint8_t *start = (uint8_t*)&hdr[1], *odata;
	uint16_t otype, olen;

	uint8_t *clid_data = NULL, clid_len = 0;
	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID) {
			clid_data = odata;
			clid_len = olen;
			break;
		}
	}

	if (!clid_data)
		goto out;

	update(iface);

	dhcpv6_for_each_option(start, end, otype, olen, odata) {
		if (otype != DHCPV6_OPT_IA_PD)
			continue;

		struct dhcpv6_ia_hdr *ia = (struct dhcpv6_ia_hdr*)&odata[-4];
		uint8_t reqlen = 62;
		uint32_t reqhint = 0;

		uint8_t *sdata;
		uint16_t stype, slen;
		dhcpv6_for_each_option(&ia[1], odata + olen, stype, slen, sdata) {
			if (stype == DHCPV6_OPT_IA_PREFIX && slen >= sizeof(struct dhcpv6_ia_prefix) - 4) {
				struct dhcpv6_ia_prefix *p = (struct dhcpv6_ia_prefix*)&sdata[-4];
				if (p->prefix) {
					reqlen = p->prefix;
					reqhint = ntohl(p->addr.s6_addr32[1]);
				}
				break;
			}
		}

		if (reqlen > 64)
			reqlen = 64;

		if (hdr->msg_type == DHCPV6_MSG_SOLICIT || hdr->msg_type == DHCPV6_MSG_REQUEST) {
			struct assignment *a = calloc(1, sizeof(*a) + clid_len);
			a->clid_len = clid_len;
			a->iaid = ia->iaid;
			a->length = reqlen;
			a->peer = *addr;
			a->assigned = reqhint;
			relayd_urandom(a->key, sizeof(a->key));
			memcpy(a->clid_data, clid_data, clid_len);

			bool assigned;
			while (!(assigned = assign(iface, a)) && ++a->length <= 64);

			uint16_t status = (assigned) ? DHCPV6_STATUS_OK : DHCPV6_STATUS_NOPREFIXAVAIL;
			if (hdr->msg_type == DHCPV6_MSG_SOLICIT) {
				*buf++ = 0;
				*buf++ = DHCPV6_OPT_RECONF_ACCEPT;
				*buf++ = 0;
				*buf++ = 0;
				buflen -= 4;
			} else if (hdr->msg_type == DHCPV6_MSG_REQUEST) {
				struct dhcpv6_auth_reconfigure auth = {
					htons(DHCPV6_OPT_AUTH),
					htons(sizeof(auth) - 4),
					3, 1, 0,
					{htonl(time(NULL)), htonl(++serial)},
					1,
					{0}
				};
				memcpy(auth.key, a->key, sizeof(a->key));
				memcpy(buf, &auth, sizeof(auth));
				buf += sizeof(auth);
				buflen -= sizeof(auth);
			}

			append_reply(buf, buflen, status, ia, a, iface);

			// Was only a solicitation so remove binding
			if (assigned && hdr->msg_type == DHCPV6_MSG_SOLICIT) {
				list_del(&a->head);
				assigned = false;
			}

			if (!assigned)
				free(a);
		} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
				hdr->msg_type == DHCPV6_MSG_RELEASE ||
				hdr->msg_type == DHCPV6_MSG_REBIND) {
			struct assignment *a = find(iface, clid_data, clid_len, ia->iaid);
			if (!a && hdr->msg_type != DHCPV6_MSG_REBIND) {
				append_reply(buf, buflen, DHCPV6_STATUS_NOBINDING, ia, a, iface);
			} else if (hdr->msg_type == DHCPV6_MSG_RENEW ||
					hdr->msg_type == DHCPV6_MSG_REBIND) {
				a->reconf_cnt = 0;
				a->reconf_sent = 0;
				append_reply(buf, buflen, DHCPV6_STATUS_OK, ia, a, iface);
			} else if (hdr->msg_type == DHCPV6_MSG_RELEASE) {
				list_del(&a->head);
				free(a);
			}
		}
	}

out:
	return response_len;
}
