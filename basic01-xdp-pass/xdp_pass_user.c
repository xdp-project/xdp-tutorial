/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "common_user.h"

static const struct option long_options[] = {
	{"help",        no_argument,		NULL, 'h' },
	{"dev",         required_argument,	NULL, 'd' },
	{"skb-mode",    no_argument,		NULL, 'S' },
	{"native-mode", no_argument,		NULL, 'N' },
	{"force",       no_argument,		NULL, 'F' },
	{"unload",      no_argument,		NULL, 'U' },
	{0, 0, NULL,  0 }
};

static int xdp_unload(int ifindex, __u32 xdp_flags)
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
	char filename[256];
	int prog_fd, err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.ifindex   = -1,
		.do_unload = false,
	};

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options);
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_unload(cfg.ifindex, cfg.xdp_flags);

	/* Locate BPF-ELF object file:  xdp_pass_kern.o */
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

        /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
         * loading this into the kernel via bpf-syscall
         */
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return EXIT_FAIL;

	if (!prog_fd) {
		fprintf(stderr, "ERR: load_bpf_file: %s\n", strerror(errno));
		return EXIT_FAIL;
	}

        /* At this point: BPF-prog is (only) loaded by the kernel, and prog_fd
         * is our file-descriptor handle. Next step is attaching this FD to a
         * kernel hook point, in this case XDP net_device link-level hook.
         * Fortunately libbpf have a helper for this:
         */
	err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, cfg.xdp_flags);
	if (err < 0) {
		fprintf(stderr, "ERR: link set xdp fd failed (err=%d): %s\n",
			err, strerror(-err));
		if (-err == EBUSY) {
			fprintf(stderr, "INFO: XDP already loaded on device:%s"
				" use --force to swap/replace\n", cfg.ifname);
		}
		return EXIT_FAIL_XDP;
	}

        /* This step is not really needed */
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Load XDP prog id=%d on device:%s ifindex:%d\n",
		info.id, cfg.ifname, cfg.ifindex);
	return EXIT_OK;
}
