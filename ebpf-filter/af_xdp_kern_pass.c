/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h" /* defines: struct datarec; */


SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	return XDP_PASS;  // Processing done by the revised default program
}

char _license[] SEC("license") = "GPL";
