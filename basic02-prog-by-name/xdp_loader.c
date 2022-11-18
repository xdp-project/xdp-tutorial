/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Specify BPF-object --filename to load \n"
	" - and select BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_pass_func";

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

	{{"offload-mode",no_argument,		NULL, 3 },
	 "Hardware offload XDP program to NIC"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

/* Lesson#1: More advanced load_bpf_object_file and bpf_object */


/* Lesson#2: This is a central piece of this lesson:
 * - Notice how BPF-ELF obj can have several programs
 * - Find by sec name via: bpf_object__find_program_by_title()
 */
struct xdp_program *__load_bpf_and_xdp_attach(struct config *cfg)
{
	/* In next assignment this will be moved into ../common/ */
	int prog_fd = -1;
	int err;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = cfg->filename;
	xdp_opts.prog_name = cfg->progsec;
	xdp_opts.opts = &opts;

	/* If flags indicate hardware offload, supply ifindex */
	/* if (cfg->xdp_flags & XDP_FLAGS_HW_MODE) */
	/* 	offload_ifindex = cfg->ifindex; */

	struct xdp_program *prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_program__attach(prog, cfg->ifindex, XDP_MODE_SKB, 0);
	if (err)
		exit(err);

	prog_fd = xdp_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: xdp_program__fd failed: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}

	return prog;
}

/* static void list_avail_progs(struct bpf_object *obj) */
/* { */
	/* struct bpf_program *pos; */

	/* printf("BPF object (%s) listing avail --progsec names\n", */
	/*        bpf_object__name(obj)); */

	/* bpf_object__for_each_program(pos, obj) { */
	/* 	if (bpf_program__is_xdp(pos)) */
	/* 		printf(" %s\n", bpf_program__title(pos, false)); */
	/* } */
/* } */

int main(int argc, char **argv)
{
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change these */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	/* if (cfg.do_unload) */
	/* 	return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */

	struct xdp_program *prog = __load_bpf_and_xdp_attach(&cfg);
	if (!prog)
		return EXIT_FAIL_BPF;

	/* if (verbose) */
	/* 	list_avail_progs(bpf_obj); */

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}
	/* Other BPF section programs will get freed on exit */
	return EXIT_OK;
}
