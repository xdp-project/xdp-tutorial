/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

SEC("xdp_pass")
int  xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_drop")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("xdp_aborted")
int  xdp_aborted_func(struct xdp_md *ctx)
{
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
