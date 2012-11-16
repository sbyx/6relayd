#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

struct icmpv6_opt {
	uint8_t type;
	uint8_t len;
	uint8_t data[6];
};


#define icmpv6_for_each_option(opt, start, end)\
	for (opt = (struct icmpv6_opt*)(start);\
	(void*)(opt + 1) <= (void*)(end) && opt->len > 0 &&\
	(void*)(opt + opt->len) <= (void*)(end); opt += opt->len)


#define MaxRtrAdvInterval 600
#define MinRtrAdvInterval (MaxRtrAdvInterval / 3)

#define ND_RA_FLAG_PROXY    0x4
