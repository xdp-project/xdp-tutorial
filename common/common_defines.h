#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	char filename[512];
	char progsec[32];
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
