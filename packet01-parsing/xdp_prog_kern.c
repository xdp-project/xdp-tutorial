/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6hdr;
	__u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_DROP;

	ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return XDP_DROP;

	if (ip6h->nexthdr != IPPROTO_ICMPV6)
		return XDP_DROP;

	nh_off += sizeof(*ip6h);
	icmp6hdr = data + nh_off;
	if (icmp6hdr + 1 > data_end)
		return XDP_DROP;

	if (icmp6hdr->icmp6_type != ICMPV6_ECHO_REQUEST)
		return XDP_DROP;

	if (bpf_ntohs(icmp6hdr->icmp6_sequence) % 2 == 0)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
