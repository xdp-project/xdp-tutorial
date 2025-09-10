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
#include "../common/common_user_bpf_xdp.h"

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

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"unload-all",  no_argument,           NULL,  4  },
	 "Unload all XDP programs on device"},

	{{0, 0, NULL,  0 }, NULL, false}
};


int main(int argc, char **argv)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char filename[] = "xdp_pass_kern.o";
	char progname[] = "xdp_prog_simple";
	struct xdp_program *prog;
	char errmsg[1024];
	int prog_fd, err; // = EXIT_SUCCESS;

	struct config cfg = {
		.attach_mode = XDP_MODE_UNSPEC,
		.ifindex   = -1,
		.do_unload = false,
	};

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
			    .open_filename = filename,
			    .prog_name = progname,
			    .opts = &bpf_opts);

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload a program by prog_id, or
	 * unload all programs on net device
	 */
	if (cfg.do_unload || cfg.unload_all) {
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %s: %s\n",
				progname, errmsg);
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", progname);
		return EXIT_OK;
	}

	/* Create an xdp_program froma a BPF ELF object file */
	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't get XDP program %s: %s\n",
			progname, errmsg);
		return err;
	}

	/* Attach the xdp_program to the net device XDP hook */
	err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			cfg.ifname, errmsg, err);
		return err;
	}

	/* This step is not really needed , BPF-info via bpf-syscall */
	prog_fd = xdp_program__fd(prog);
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
