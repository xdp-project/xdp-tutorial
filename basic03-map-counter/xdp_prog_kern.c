/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"

/* Common stats data record (shared with userspace)
 * TODO: Move this into common_kern_user.h
*/
struct datarec {
        __u64 rx_packets;
};

struct bpf_map_def SEC("maps") stats_map = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .key_size       = sizeof(__u32),
        .value_size     = sizeof(struct datarec),
        .max_entries    = 1,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 key = 0;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup 0 always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
