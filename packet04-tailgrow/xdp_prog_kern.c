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

/* Solution to packet03/assignment-2 */
SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char dst[ETH_ALEN] = { /* TODO: put your values here */ };
	unsigned ifindex = 0/* TODO: put your values here */;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect(ifindex, 0);

out:
	return xdp_stats_record_action(ctx, action);
}

/* Solution to packet03/assignment-3 */
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

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_tailgrow")
int xdp_tailgrow_func(struct xdp_md *ctx)
{
//	void *data_end = (void *)(long)ctx->data_end;
//	void *data = (void *)(long)ctx->data;
	//struct hdr_cursor nh;
	int offset;

	offset = 10;
	bpf_xdp_adjust_tail(ctx, offset);
	return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_tailgrow_tx")
int xdp_tailgrow_func2(struct xdp_md *ctx)
{
//	void *data_end = (void *)(long)ctx->data_end;
//	void *data = (void *)(long)ctx->data;
	//struct hdr_cursor nh;
	int offset;

	offset = 32;
	bpf_xdp_adjust_tail(ctx, offset);
	return xdp_stats_record_action(ctx, XDP_TX);
}

SEC("xdp_tx")
int xdp_tx_func(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_TX);
}

struct my_timestamp {
	__u16 magic;
	__u64 time;
} __attribute__((packed));

SEC("xdp_tailgrow_use")
int xdp_tailgrow3(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	//struct hdr_cursor nh;
	int offset;
	struct my_timestamp *ts;

	offset = 8;
//	if (data + offset > data_end)
//		return XDP_ABORTED;

	bpf_xdp_adjust_tail(ctx, offset);
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if (data + offset > data_end)
		return XDP_ABORTED;
//	if (data + 2048 > data_end)
//		return XDP_ABORTED;

	ts = data;
//	ts->time = 42;

	return xdp_stats_record_action(ctx, XDP_PASS);
}


#define compiler_barrier() __asm__ __volatile__("": : :"memory")

SEC("xdp_tailgrow_parse")
int grow_parse(struct xdp_md *ctx)
{
	void *data_end; // = (void *)(long)ctx->data_end;
	void *data; // = (void *)(long)ctx->data;

	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct hdr_cursor nh;

	__u16 ip_tot_len;

	struct my_timestamp *ts;

	/* Increase packet size and reload data pointers */
	__u8 offset = sizeof(*ts);
	bpf_xdp_adjust_tail(ctx, offset);
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
//	compiler_barrier();

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

char _license[] SEC("license") = "GPL";
