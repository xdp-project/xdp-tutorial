/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include "common_defines.h"

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	char filename[512];
	char progsec[32];
};

void usage(const char *prog_name, const char *doc,
           const struct option *long_options);

void parse_cmdline_args(int argc, char **argv,
			const struct option *long_options,
                        struct config *cfg, const char *doc);

#endif /* __COMMON_PARAMS_H */
