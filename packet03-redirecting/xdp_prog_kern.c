/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	/* Assignment 1: swap source and destination addresses in the eth.
	 * For simplicity you can use the memcpy macro defined above */
}

static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	/* Assignment 1: swap source and destination addresses in the iphv6dr */
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	/* Assignment 1: swap source and destination addresses in the iphdr */
}

/* Implement packet03/assignment-1 in this section */
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply;
	struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);

	/* Assignment 1: patch the packet and update the checksum. You can use
	 * the echo_reply variable defined above to fix the ICMP Type field. */

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

/* Assignment 2 */
SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	/* unsigned char dst[ETH_ALEN] = {} */	/* Assignment 2: fill in with the MAC address of the left inner interface */
	/* unsigned ifindex = 0; */		/* Assignment 2: fill in with the ifindex of the left interface */

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Assignment 2: set a proper destination address and call the
	 * bpf_redirect() with proper parameters, action = bpf_redirect(...) */

out:
	return xdp_stats_record_action(ctx, action);
}

/* Assignment 3: nothing to do here, patch the xdp_prog_user.c program */
SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char *dst;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Do we know where to redirect this packet? */
	dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	if (!dst)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	/* Assignment 4: see samples/bpf/xdp_fwd_kern.c from the kernel */
	return --iph->ttl;
}

/* Assignment 4: Complete this router program */
SEC("xdp_router")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET case */
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		/* These pointers can be used to assign structures instead of executing memcpy: */
		/* struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src; */
		/* struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst; */

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		/* Assignment 4: fill the fib_params structure for the AF_INET6 case */
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		/* Assignment 4: fill in the eth destination and source
		 * addresses and call the bpf_redirect_map function */
		/* memcpy(eth->h_dest, ???, ETH_ALEN); */
		/* memcpy(eth->h_source, ???, ETH_ALEN); */
		/* action = bpf_redirect_map(&tx_port, ???, 0); */
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
