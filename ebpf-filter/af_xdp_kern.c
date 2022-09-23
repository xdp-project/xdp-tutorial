/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map_0 SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map_1 SEC(".maps") ;

SEC("xdp_sock_0")
int xdp_sock_prog_0(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map_0, &index))
        return bpf_redirect_map(&xsks_map_0, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
