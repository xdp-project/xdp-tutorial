/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

        /* These keep track of the next header type and a pointer to it */
	void *nh_ptr = data;
	int nh_type;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh_ptr, data_end, &eth);

        if (nh_type == ETH_P_IPV6) {
                struct ipv6hdr *ip6h;
                struct icmp6hdr *icmp6h;

                nh_type = parse_ip6hdr(&nh_ptr, data_end, &ip6h);
                if (nh_type != IPPROTO_ICMPV6)
                        goto out;

                nh_type = parse_icmp6hdr(&nh_ptr, data_end, &icmp6h);
                if (nh_type != ICMPV6_ECHO_REQUEST)
                        goto out;

                if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
                        return XDP_DROP;

        } else if (nh_type == ETH_P_IP) {
                struct iphdr *iph;
                struct icmphdr *icmph;

                nh_type = parse_iphdr(&nh_ptr, data_end, &iph);
                if (nh_type != IPPROTO_ICMP)
                        goto out;

                nh_type = parse_icmphdr(&nh_ptr, data_end, &icmph);
                if (nh_type != ICMP_ECHO)
                        goto out;

                if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
                        return XDP_DROP;

        }

out:
	/* Everything we couldn't parse, or that we don't want to deal with, we
	 * just pass up the stack and let the kernel deal with it.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
