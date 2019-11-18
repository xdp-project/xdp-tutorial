/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains functions that are used in the packetXX XDP programs to
 * manipulate on packets data. The functions are marked as __always_inline, and
 * fully defined in this header file to be included in the BPF program.
 */

#ifndef __REWRITE_HELPERS_H
#define __REWRITE_HELPERS_H

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid;

	if (!proto_is_vlan(eth->h_proto))
		return -1;

	/* Careful with the parenthesis here */
	vlh = (void *)(eth + 1);

	/* Still need to do bounds checking */
	if (vlh + 1 > data_end)
		return -1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlid = bpf_ntohs(vlh->h_vlan_TCI);
	h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (eth + 1 > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
		struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if (eth + 1 > data_end)
		return -1;

	/* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)(eth + 1);

	if (vlh + 1 > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}

/*
 * Swaps destination and source MAC addresses inside an Ethernet header
 */
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/*
 * Swaps destination and source IPv6 addresses inside an IPv6 header
 */
static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	struct in6_addr tmp = ipv6->saddr;

	ipv6->saddr = ipv6->daddr;
	ipv6->daddr = tmp;
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

#endif /* __REWRITE_HELPERS_H */
