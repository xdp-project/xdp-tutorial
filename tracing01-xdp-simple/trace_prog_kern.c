/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(__s32),
	.value_size  = sizeof(__u64),
	.max_entries = 10,
};

struct xdp_exception_ctx {
	__u64 __pad;      // First 8 bytes are not accessible by bpf code
	__s32 prog_id;    //      offset:8;  size:4; signed:1;
	__u32 act;        //      offset:12; size:4; signed:0;
	__s32 ifindex;    //      offset:16; size:4; signed:1;
};

SEC("tracepoint/xdp/xdp_exception")
int trace_xdp_exception(struct xdp_exception_ctx *ctx)
{
	__s32 key = ctx->ifindex;
	__u32 *valp;

	/* Collecting stats only for XDP_ABORTED action. */
	if (ctx->act != XDP_ABORTED)
		return 0;

	/* Lookup in kernel BPF-side returns pointer to actual data. */
	valp = bpf_map_lookup_elem(&xdp_stats_map, &key);

	/* If there's no record for interface, we need to create one,
	 * with number of packets == 1
	 */
	if (!valp) {
		__u64 one = 1;
		return bpf_map_update_elem(&xdp_stats_map, &key, &one, 0) ? 1 : 0;
	}

	(*valp)++;
	return 0;
}

char _license[] SEC("license") = "GPL";
