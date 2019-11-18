// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
//#include "../common/parsing_helpers.h"
/*
 * NOTICE: Copied over parts of ../common/parsing_helpers.h
 *         to make it easier to point out compiler optimizations
 */

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
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
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

SEC("xdp_vlan01")
int xdp_vlan_01(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_ABORTED;

	/* The LLVM compiler is very clever, and will remove above walking of
	 * VLAN headers (the loop unroll).
	 *
	 * The returned value nh_type, variable (__u16) h_proto in
	 * parse_ethhdr(), is only compared against a negative value (signed).
	 * The compile see that it can remove the VLAN loop, because:
	 *  1. h_proto = vlh->h_vlan_encapsulated_proto can only be >= 0
	 *  2. we never read nh->pos (so it removes nh->pos = vlh;).
	 */

	/* Accessing eth pointer is still valid after compiler optimization */
	if (proto_is_vlan(eth->h_proto))
		return XDP_DROP;

	/* Hint: to inspect BPF byte-code run:
	 *  llvm-objdump -S xdp_vlan01_kern.o
	 */
	return XDP_PASS;
}
