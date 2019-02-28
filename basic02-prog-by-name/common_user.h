/* This common_user.h is used by userspace programs */
#ifndef __COMMON_USER_H
#define __COMMON_USER_H

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	char filename[512];
	char progsec[32];
};

/* Exit return codes */
#define EXIT_OK		0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

void usage(const char *prog_name, const char *doc,
           const struct option *long_options);

void parse_cmdline_args(int argc, char **argv,
			const struct option *long_options,
                        struct config *cfg, const char *doc);

#endif /* __COMMON_USER_H */
