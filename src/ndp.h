#pragma once
#include "6relayd.h"
#include "list.h"
#include <time.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define NDP_MAX_NEIGHBORS 1000

struct ndp_neighbor {
	struct list_head head;
	struct relayd_interface *iface;
	struct in6_addr addr;
	time_t timeout;
};
