/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 */

SEC("xdp1")
int  xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp2")
int  xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("xdp3")
int  xdp_aborted(struct xdp_md *ctx)
{
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";
