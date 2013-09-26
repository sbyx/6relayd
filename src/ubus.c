#include <syslog.h>
#include <libubus.h>
#include <arpa/inet.h>

#include "6relayd.h"
#include "dhcpv6.h"
#include "dhcpv4.h"


static struct ubus_context *ubus = NULL;
static struct ubus_subscriber netifd;
static struct blob_buf b;
static void handle_ubus(_unused struct relayd_event *event)
{
	ubus_handle_event(ubus);
}

static struct relayd_event ubus_event = {-1, handle_ubus, NULL};

enum {
        DEV_NAME,
        DEV_ARGS,
        __DEV_MAX,
};

static const struct blobmsg_policy dev_policy[__DEV_MAX] = {
        [DEV_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
        [DEV_ARGS] = { .name = "args", .type = BLOBMSG_TYPE_ARRAY },
};


static int handle_enable(_unused struct ubus_context *ctx, _unused struct ubus_object *obj,
		_unused struct ubus_request_data *req, _unused const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DEV_MAX];
	blobmsg_parse(dev_policy, __DEV_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[DEV_NAME] || !tb[DEV_ARGS])
		return UBUS_STATUS_INVALID_ARGUMENT;

	char *argv[256], **argc = argv;
	*argc++ = blobmsg_get_string(tb[DEV_NAME]);

	struct blob_attr *cur;
	size_t rem;

	blobmsg_for_each_attr(cur, tb[DEV_ARGS], rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return UBUS_STATUS_INVALID_ARGUMENT;

		*argc++ = blobmsg_get_string(cur);

		if ((size_t)(argc - argv) >= ARRAY_SIZE(argv))
			break;
	}

	if (!relayd_open_interface(argv, argc - argv))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return UBUS_STATUS_OK;
}


static int handle_disable(_unused struct ubus_context *ctx, _unused struct ubus_object *obj,
		_unused struct ubus_request_data *req, _unused const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DEV_MAX];
	blobmsg_parse(dev_policy, __DEV_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[DEV_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	const char *ifname = blobmsg_get_string(tb[DEV_NAME]);
	struct relayd_interface *iface = relayd_get_interface_by_name(ifname);

	if (!iface)
		return UBUS_STATUS_NOT_FOUND;

	relayd_close_interface(iface);
	return UBUS_STATUS_OK;
}


static int handle_dhcpv4_leases(struct ubus_context *ctx, _unused struct ubus_object *obj,
		struct ubus_request_data *req, _unused const char *method,
		_unused struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	void *a = blobmsg_open_table(&b, "device");
	time_t now = relayd_monotonic_time();

	struct relayd_interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv4 != RELAYD_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");

		struct dhcpv4_assignment *lease;
		list_for_each_entry(lease, &iface->dhcpv4_assignments, head) {
			if (lease->valid_until < now)
				continue;

			void *l = blobmsg_open_table(&b, NULL);

			char *buf = blobmsg_alloc_string_buffer(&b, "mac", 13);
			relayd_hexlify(buf, lease->hwaddr, sizeof(lease->hwaddr));
			blobmsg_add_string_buffer(&b);

			blobmsg_add_string(&b, "hostname", lease->hostname);

			buf = blobmsg_alloc_string_buffer(&b, "ip", INET_ADDRSTRLEN);
			struct in_addr addr = {htonl(lease->addr)};
			inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "valid", now - lease->valid_until);

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, a);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}


static int handle_dhcpv6_leases(_unused struct ubus_context *ctx, _unused struct ubus_object *obj,
		_unused struct ubus_request_data *req, _unused const char *method,
		_unused struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	void *a = blobmsg_open_table(&b, "device");
	time_t now = relayd_monotonic_time();

	struct relayd_interface *iface;
	list_for_each_entry(iface, &interfaces, head) {
		if (iface->dhcpv6 != RELAYD_SERVER)
			continue;

		void *i = blobmsg_open_table(&b, iface->ifname);
		void *j = blobmsg_open_array(&b, "leases");

		struct dhcpv6_assignment *lease;
		list_for_each_entry(lease, &iface->ia_assignments, head) {
			if (lease->valid_until < now)
				continue;

			void *l = blobmsg_open_table(&b, NULL);

			char *buf = blobmsg_alloc_string_buffer(&b, "duid", 264);
			relayd_hexlify(buf, lease->clid_data, lease->clid_len);
			blobmsg_add_string_buffer(&b);

			blobmsg_add_u32(&b, "iaid", ntohl(lease->iaid));
			blobmsg_add_string(&b, "hostname", (lease->hostname) ? lease->hostname : "");
			blobmsg_add_u32(&b, "assigned", lease->assigned);
			blobmsg_add_u32(&b, "length", lease->length);

			void *m = blobmsg_open_array(&b, "ipv6");
			struct in6_addr addr;
			for (size_t i = 0; i < iface->ia_addr_len; ++i) {
				if (iface->ia_addr[i].prefix > 64)
					continue;

				addr = iface->ia_addr[i].addr;
				if (lease->length == 128)
					addr.s6_addr32[3] = htonl(lease->assigned);
				else
					addr.s6_addr32[1] |= htonl(lease->assigned);

				char *c = blobmsg_alloc_string_buffer(&b, NULL, INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &addr, c, INET6_ADDRSTRLEN);
				blobmsg_add_string_buffer(&b);
			}
			blobmsg_close_table(&b, m);

			blobmsg_add_u32(&b, "valid", now - lease->valid_until);

			blobmsg_close_table(&b, l);
		}

		blobmsg_close_array(&b, j);
		blobmsg_close_table(&b, i);
	}

	blobmsg_close_table(&b, a);
	ubus_send_reply(ctx, req, b.head);
	return 0;
}


static struct ubus_method main_object_methods[] = {
	UBUS_METHOD("enable", handle_enable, dev_policy),
	UBUS_METHOD("disable", handle_disable, dev_policy),
	{.name = "get_dhcpv4_leases", .handler = handle_dhcpv4_leases},
	{.name = "get_dhcpv6_leases", .handler = handle_dhcpv6_leases},
};

static struct ubus_object_type main_object_type =
		UBUS_OBJECT_TYPE("6relayd", main_object_methods);

static struct ubus_object main_object = {
        .name = "6relayd",
        .type = &main_object_type,
        .methods = main_object_methods,
        .n_methods = ARRAY_SIZE(main_object_methods),
};


static void subscribe_netifd(void)
{
	// TODO: watch ubus.object.add events
	uint32_t id;
	if (!ubus_lookup_id(ubus, "network.interface", &id))
		ubus_subscribe(ubus, &netifd, id);
}


int init_ubus(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		syslog(LOG_ERR, "Unable to connect to ubus: %s", strerror(errno));
		return -1;
	}

	ubus_event.socket = ubus->sock.fd;
	relayd_register_event(&ubus_event);

	ubus_add_object(ubus, &main_object);
	subscribe_netifd();

	return 0;
}

