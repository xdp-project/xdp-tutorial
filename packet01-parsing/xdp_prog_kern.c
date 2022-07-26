/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};
static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}
enum {
	k_vlan_limit=8
};
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	int vlan_index;

	for(vlan_index=0; vlan_index<k_vlan_limit; vlan_index += 1)
	{
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	if (!proto_is_vlan(eth->h_proto)) break;
	}
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6h; /* Network byte order */

	return 0;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
		                        void *data_end,
					struct iphdr **ip4hdr)
{
	struct iphdr *ip4h = nh->pos;
	int hdrsize = sizeof(*ip4h);
	if (nh->pos + hdrsize >data_end)
		return -1;
	int actual_hdrsize = ip4h->ihl*4;
	if (nh->pos + actual_hdrsize > data_end)
		return -1;
	nh->pos += actual_hdrsize;
	*ip4hdr = ip4h; /* Network byte order */
	return 0;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;
	int hdrsize = sizeof(*icmp6h);
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6h; /* Network byte order */

	return 0;
}
static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = nh->pos;
	int hdrsize = sizeof(*icmph);
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmph; /* Network byte order */

	return 0;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6))
	{

	/* Assignment additions go below here */
	struct ipv6hdr *ip6hdr;
	int rc;
	rc = parse_ip6hdr(&nh, data_end, &ip6hdr);
	if (rc != 0)
		goto out;

	/* Need to duck out if the packet is not icmp */


	struct icmp6hdr *ic6hdr;
	rc = parse_icmp6hdr(&nh, data_end, &ic6hdr);
	if (rc != 0)
		goto out;

	int sequence = bpf_ntohs(ic6hdr->icmp6_sequence);

	action = (sequence & 1) ? XDP_PASS : XDP_DROP;
	}
	else if (nh_type == bpf_htons(ETH_P_IP))
	{
		        /* Assignment additions go below here */
        struct iphdr *iphdr;
        int rc;
        rc = parse_ip4hdr(&nh, data_end, &iphdr);
        if (rc != 0)
                goto out;

        /* Need to duck out if the packet is not icmp */


        struct icmphdr *ichdr;
        rc = parse_icmphdr(&nh, data_end, &ichdr);
        if (rc != 0)
                goto out;

        int sequence = bpf_ntohs(ichdr->un.echo.sequence);

        action = (sequence & 1) ? XDP_PASS : XDP_DROP;

	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
