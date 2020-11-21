// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
#include "../common/parsing_helpers.h"

#if 0
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};
#endif

#if 0 /* moved to parsing_helpers.h */
/* Based on parse_ethhdr() */
static __always_inline int __parse_ethhdr_vlan(struct hdr_cursor *nh,
					       void *data_end,
					       struct ethhdr **ethhdr,
					       struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) {
			vlans->id[i] =
				bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
		}
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}
#endif

SEC("xdp_vlan02")
int xdp_vlan_02(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int eth_type;
	nh.pos = data;

	struct collect_vlans vlans;

	struct ethhdr *eth;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (eth_type < 0)
		return XDP_ABORTED;
	/* The eth_type have skipped VLAN-types, but collected VLAN ids. The
	 * eth ptr still points to Ethernet header, thus to check if this is a
	 * VLAN packet do proto_is_vlan(eth->h_proto).
	 */

	/* The LLVM compiler is very clever, it sees that program only access
	 * 2nd "inner" vlan (array index 1), and only does loop unroll of 2, and
	 * only does the VLAN_VID_MASK in the 2nd "inner" vlan case.
	 */
	if (vlans.id[1] == 42)
		return XDP_ABORTED;

	/* If using eth_type (even compare against zero), it will cause full
	 * loop unroll and walking all VLANs (for VLAN_MAX_DEPTH). Still only
	 * "inner" VLAN is masked out.
	 */
#if 0
	if (eth_type == 0)
		return XDP_PASS;
#endif

	/* Unless we only want to manipulate VLAN, then next step will naturally
	 * be parsing the next L3 headers. This (also) cause compiler to create
	 * VLAN loop, as this uses nh->pos
	 */
#if 0
	int ip_type;
	struct iphdr *iphdr;
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (eth_type < 0)
			return XDP_ABORTED;

		if (ip_type == IPPROTO_UDP)
			return XDP_DROP;
	}
#endif
	/* Hint: to inspect BPF byte-code run:
	 *  llvm-objdump --no-show-raw-insn -S xdp_vlan02_kern.o
	 */
	return XDP_PASS;
}
