/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_stats1";

static const struct option long_options[] = {
	{"help",        no_argument,		NULL, 'h' },
	{"dev",         required_argument,	NULL, 'd' },
	{"skb-mode",    no_argument,		NULL, 'S' },
	{"native-mode", no_argument,		NULL, 'N' },
	{"auto-mode",   no_argument,		NULL, 'A' },
	{"force",       no_argument,		NULL, 'F' },
	{"unload",      no_argument,		NULL, 'U' },
	{"quiet",       no_argument,		NULL, 'q' },
	{"filename",    required_argument,	NULL,  1  },
	{"progsec",    required_argument,	NULL,  2  },
	{0, 0, NULL,  0 }
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	char pin_dir[PATH_MAX];
	int err, len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options);
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	/* Use the --dev name as subdir for exporting/pinning maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
		printf(" - Pinning maps in %s/\n", pin_dir);
	}

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err) {
		fprintf(stderr, "ERR: pinning maps in %s\n", pin_dir);
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}
