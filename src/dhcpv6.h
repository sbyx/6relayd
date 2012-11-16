/**
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

#define ALL_DHCPV6_RELAYS {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02}}}

#define ALL_DHCPV6_SERVERS {{{0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03}}}

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define DHCPV6_MSG_SOLICIT 1
#define DHCPV6_MSG_ADVERTISE 2
#define DHCPV6_MSG_REBIND 6
#define DHCPV6_MSG_REPLY 7
#define DHCPV6_MSG_RECONFIGURE 10
#define DHCPV6_MSG_INFORMATION_REQUEST 11
#define DHCPV6_MSG_RELAY_FORW 12
#define DHCPV6_MSG_RELAY_REPL 13

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_STATUS 13
#define DHCPV6_OPT_RELAY_MSG 9
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_INTERFACE_ID 18
#define DHCPV6_OPT_DNS_SERVERS 23

#define DHCPV6_DUID_VENDOR 2
#define DHCPV6_STATUS_NOADDRSAVAIL 2

// I just remembered I have an old one lying around...
#define DHCPV6_ENT_NO  30462
#define DHCPV6_ENT_TYPE 1


#define DHCPV6_HOP_COUNT_LIMIT 32

struct dhcpv6_client_header {
	uint8_t msg_type;
	uint8_t transaction_id[3];
	uint8_t options[];
} __attribute__((packed));

struct dhcpv6_relay_header {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint8_t options[];
} __attribute__((packed));

struct dhcpv6_relay_forward_envelope {
	uint8_t msg_type;
	uint8_t hop_count;
	struct in6_addr link_address;
	struct in6_addr peer_address;
	uint16_t interface_id_type;
	uint16_t interface_id_len;
	uint32_t interface_id_data;
	uint16_t relay_message_type;
	uint16_t relay_message_len;
} __attribute__((packed));

struct dhcpv6_broken_duid {
	uint16_t duid_type;
	uint32_t vendor;
	uint16_t subtype;
	uint32_t iface_index;
	struct in6_addr link_addr;
} __attribute__((packed));


#define dhcpv6_for_each_option(start, end, otype, olen, odata)\
	for (uint8_t *_o = (uint8_t*)(start); _o + 4 <= (end) &&\
		((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void*)&_o[4]) &&\
		((olen) = _o[2] << 8 | _o[3]) + (odata) <= (end); \
		_o += 4 + (_o[2] << 8 | _o[3]))
