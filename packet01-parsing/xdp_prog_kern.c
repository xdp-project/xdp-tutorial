/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

static __always_inline struct ethhdr *get_ethhdr(void **nexthdr, void *data_end)
{
	struct ethhdr *eth = *nexthdr;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (*nexthdr + hdrsize > data_end)
		return NULL;

	*nexthdr += hdrsize;
	return eth;
}

static __always_inline struct ipv6hdr *get_ip6hdr(struct ethhdr *eth,
						 void **nexthdr,
						 void *data_end)
{
	struct ipv6hdr *ip6h = *nexthdr;

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return NULL;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return NULL;

	*nexthdr = ip6h + 1;
	return ip6h;
}

static __always_inline struct icmp6hdr *get_icmp6hdr(struct ipv6hdr *ip6h,
						    void **nexthdr,
						    void *data_end)
{
	struct icmp6hdr *icmp6h = *nexthdr;

	if (ip6h->nexthdr != IPPROTO_ICMPV6)
		return NULL;

	if (icmp6h + 1 > data_end)
		return NULL;

	*nexthdr = icmp6h + 1;
	return icmp6h;
}


SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *nexthdr = data;

	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	eth = get_ethhdr(&nexthdr, data_end);
	if (!eth)
		goto out;

	ip6h = get_ip6hdr(eth, &nexthdr, data_end);
	if (!ip6h)
		goto out;

	icmp6h = get_icmp6hdr(ip6h, &nexthdr, data_end);
	if (!icmp6h)
		goto out;

	/* Perform the actual function we wanted, namely to drop all
	 * even-numbered ping packets.
	 */
	if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST &&
	    bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
		return XDP_DROP;

out:
	/* Everything we couldn't parse, or that we don't want to deal with, we
	 * just pass up the stack and let the kernel deal with it.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
