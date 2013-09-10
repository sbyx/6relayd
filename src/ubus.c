#include <syslog.h>
#include <libubus.h>

#include "6relayd.h"


static struct ubus_context *ubus = NULL;
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


static struct ubus_method main_object_methods[] = {
	UBUS_METHOD("enable", handle_enable, dev_policy),
	UBUS_METHOD("disable", handle_disable, dev_policy),
};

static struct ubus_object_type main_object_type =
		UBUS_OBJECT_TYPE("6relayd", main_object_methods);

static struct ubus_object main_object = {
        .name = "6relayd",
        .type = &main_object_type,
        .methods = main_object_methods,
        .n_methods = ARRAY_SIZE(main_object_methods),
};


int init_ubus(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		syslog(LOG_ERR, "Unable to connect to ubus: %s", strerror(errno));
		return -1;
	}

	ubus_event.socket = ubus->sock.fd;
	relayd_register_event(&ubus_event);

	ubus_add_object(ubus, &main_object);
	return 0;
}

