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

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(void **nexthdr, void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = *nexthdr;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (*nexthdr + hdrsize > data_end)
		return -1;

	*nexthdr += hdrsize;
	*ethhdr = eth;

	return bpf_ntohs(eth->h_proto);
}

static __always_inline int parse_ip6hdr(void **nexthdr,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = *nexthdr;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return -1;

	*nexthdr = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_icmp6hdr(void **nexthdr,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = *nexthdr;

	if (icmp6h + 1 > data_end)
		return -1;

	*nexthdr = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

        /* These keep track of the next header type and a pointer to it */
	void *nh_ptr = data;
	int nh_type;

	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh_ptr, data_end, &eth);
	if (nh_type != ETH_P_IPV6)
		goto out;

	nh_type = parse_ip6hdr(&nh_ptr, data_end, &ip6h);
	if (nh_type != IPPROTO_ICMPV6)
		goto out;

	nh_type = parse_icmp6hdr(&nh_ptr, data_end, &icmp6h);
	if (nh_type != ICMPV6_ECHO_REQUEST)
		goto out;

	/* Perform the actual function we wanted, namely to drop all
	 * even-numbered ping packets.
	 */
	if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
		return XDP_DROP;

out:
	/* Everything we couldn't parse, or that we don't want to deal with, we
	 * just pass up the stack and let the kernel deal with it.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
