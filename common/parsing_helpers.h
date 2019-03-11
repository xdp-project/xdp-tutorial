/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file contains parsing functions that are used in the packetXX XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

/*
 * 	struct vlan_hdr - vlan header
 * 	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

#define VLAN_MAX_DEPTH 5

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
        struct vlan_hdr *vlh = *nexthdr;
        __u16 h_proto = eth->h_proto;
	struct ipv6hdr *ip6h;
        int i;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!(h_proto == bpf_htons(ETH_P_8021Q) ||
                      h_proto == bpf_htons(ETH_P_8021AD)))
                        break;

                if (vlh + 1 > data_end)
                        return NULL;

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        ip6h = (void *)vlh;

	if (h_proto != bpf_htons(ETH_P_IPV6))
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

#endif /* __PARSING_HELPERS_H */
