/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

static int ifindex = -1;
static char ifname_buf[IF_NAMESIZE];
static char *ifname;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static const struct option long_options[] = {
	{"help",        no_argument,		NULL, 'h' },
	{"dev",         required_argument,	NULL, 'd' },
	{"skb-mode",    no_argument,		NULL, 'S' },
	{"native-mode", no_argument,		NULL, 'N' },
	{"force",       no_argument,		NULL, 'F' },
	{"unload",      no_argument,		NULL, 'U' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;

	printf("\nDOCUMENTATION:\n %s\n", __doc__);
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
				*long_options[i].flag);
		else
			printf(" short-option: -%c",
				long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

/* Exit return codes */
#define EXIT_OK		0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3

static int xdp_unload(int ifindex_unload)
{
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return EXIT_FAIL_XDP;
	}
	return EXIT_OK;
}

int main(int argc, char **argv)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_object *obj;
	int prog_fd, opt, err;
	bool unload = false;
	char filename[256];
	int longindex = 0;

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:SNFU",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'N':
			xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'U':
			unload = true;
			break;
		case 'h':
		error:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
	/* Required option */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}
	if (unload)
		return xdp_unload(ifindex);

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return EXIT_FAIL;

	if (!prog_fd) {
		fprintf(stderr, "ERR: load_bpf_file: %s\n", strerror(errno));
		return EXIT_FAIL;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp fd failed (err=%d):%s\n",
			err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Load XDP prog id=%d on device:%s ifindex:%d\n",
		info.id, ifname, ifindex);
	return EXIT_OK;
}
