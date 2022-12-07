/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      required_argument,		NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{0, 0, NULL,  0 }, NULL, false}
};


enum xdp_attach_mode get_attach_mode(int ifindex)
{
	struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);

	return xdp_multiprog__attach_mode(mp);
}


int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	char filename[] = "xdp_pass_kern.o";
	char progname[] = "xdp_prog_simple";
	char errmsg[1024];
	int err = EXIT_SUCCESS;
	struct xdp_program *p;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (cfg.do_unload) {
		xdp_opts.id = cfg.prog_id;
	} else {
		xdp_opts.open_filename = filename;
		xdp_opts.prog_name = progname;
		xdp_opts.opts = &opts;
	}

	p = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(p);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't get XDP program %s: %s\n",
			progname, errmsg);
		return err;
	}

	if (cfg.do_unload)
		return xdp_program__detach(p, cfg.ifindex, get_attach_mode(cfg.ifindex), 0);

	err = xdp_program__attach(p, cfg.ifindex, get_attach_mode(cfg.ifindex), 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			cfg.ifname, errmsg, err);
		return err;
	}

	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int prog_fd = xdp_program__fd(p);

        /* This step is not really needed , BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, cfg.ifname, cfg.ifindex);
	return EXIT_OK;
}
