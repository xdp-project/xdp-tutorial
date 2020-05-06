/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

struct my_timestamp {
	__u16 magic;
	__u64 time;
} __attribute__((packed));

SEC("xdp_tailgrow_parse")
int grow_parse(struct xdp_md *ctx)
{
	void *data_end;
	void *data;
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct hdr_cursor nh;
	struct iphdr *iphdr;
	struct ethhdr *eth;
	__u16 ip_tot_len;

	struct my_timestamp *ts;

	/* Increase packet size (at tail) and reload data pointers */
	__u8 offset = sizeof(*ts);
	if (bpf_xdp_adjust_tail(ctx, offset))
		goto out;
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else {
		action = XDP_PASS;
		goto out;
	}

	/* Demo use-case: Add timestamp in extended tailroom to ICMP packets,
	 * before sending to network-stack via XDP_PASS.  This can be
	 * captured via tcpdump, and provide earlier (XDP layer) timestamp.
	 */
	if (ip_type == IPPROTO_ICMP) {

		/* Packet size in bytes, including IP header and data */
		ip_tot_len = bpf_ntohs(iphdr->tot_len);

		/*
		 * Tricks to get pass the verifier. Being allowed to use
		 * packet value iphdr->tot_len, involves bounding possible
		 * values to please verifier.
		 */
		if (ip_tot_len < 2) {
			/* This check seems strange on unsigned ip_tot_len,
			 * but is needed, else verifier complains:
			 * "unbounded min value is not allowed"
			 */
			goto out;
		}
		ip_tot_len &= 0xFFF; /* Max 4095 */

		/* Finding end of packet + offset, and bound access */
		if ((void *)iphdr + ip_tot_len + offset > data_end) {
			action = XDP_ABORTED;
			goto out;
		}

		/* Point ts to end-of-packet, that have been offset extended */
		ts = (void *)iphdr + ip_tot_len;
		ts->magic = 0x5354; /* String "TS" in network-byte-order */
		ts->time  = bpf_ktime_get_ns();
	}
out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_tailgrow")
int tailgrow_pass(struct xdp_md *ctx)
{
	int offset;

	offset = 10;
	bpf_xdp_adjust_tail(ctx, offset);
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

/* For benchmarking tail grow overhead (does a memset)*/
SEC("xdp_tailgrow_tx")
int tailgrow_tx(struct xdp_md *ctx)
{
	int offset;

	offset = 32;
	bpf_xdp_adjust_tail(ctx, offset);
	return xdp_stats_record_action(ctx, XDP_TX);
}

/* Baseline benchmark of XDP_TX */
SEC("xdp_tx")
int xdp_tx_rec(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_TX);
}

char _license[] SEC("license") = "GPL";
