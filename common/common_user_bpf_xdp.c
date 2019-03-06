#include <bpf/libbpf.h> /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common_defines.h"

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	if (!curr_prog_id) {
		if (verbose)
			printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
			       __func__, ifindex);
		return EXIT_OK;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return EXIT_FAIL;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	if (verbose)
		printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
		       __func__, curr_prog_id, ifindex);

	return EXIT_OK;
}

struct bpf_object *load_bpf_object_file(const char *filename)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* This struct allow us to set ifindex, but we currently don't use
	 * features (like hardware offload) that requires setting ifindex.
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};
	prog_load_attr.file = filename;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int prog_fd = -1;
	int err;

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	bpf_obj = load_bpf_object_file(cfg->filename);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* Find a matching BPF prog section name */
	bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: finding progsec: %s\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}
