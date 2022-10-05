/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>


#include "common_kern_user.h" /* defines: struct datarec; */

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, int);
	__type(value, struct datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps") ;

struct {
        __uint(priority, 1);
        __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

//struct {
//	__uint(type, BPF_MAP_TYPE_XSKMAP);
//	__uint(max_entries, 64);
//	__type(key, int);
//	__type(value, int);
//} xsks_map_1 SEC(".maps") ;

static __always_inline
__u32 stats_record_action(struct xdp_md *ctx, __u32 action)
{
	bpf_printk("stats_record_action action=%d\n", action);
//	return action;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

//	return action;
	return XDP_PASS;
}

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
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

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{

    int index = ctx->rx_queue_index;
    //    __u32 action = XDP_DROP; /* Default action */
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	bpf_printk("index=%d mapped=%p\n", index, mapped) ;
//    bpf_printk("index=%d mapped=%p returning XDP_PASS\n", index, mapped) ;
//	return XDP_PASS;

    __u32 action = XDP_PASS; /* Default action */
//    if (mapped)
    {
    	void *data_end = (void *)(long)ctx->data_end;
    	void *data = (void *)(long)ctx->data;
    	struct ethhdr *eth;
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
		bpf_printk("nh_type=0x%04x ETH_P_IP=0x%04x\n", nh_type, ETH_P_IP);
		if (nh_type == bpf_htons(ETH_P_IP))
			{
						/* Assignment additions go below here */
				struct iphdr *iphdr;
				int rc;
				rc = parse_ip4hdr(&nh, data_end, &iphdr);
				if (rc != 0) goto out ;

				int protocol=iphdr->protocol;
				bpf_printk("protocol=%d\n", protocol) ;
				if ( protocol == IPPROTO_UDP ) {
					action = XDP_DROP ;
					goto out;
				}

			}

		if(mapped)
		{
			bpf_printk("returning through bpf_redirect_map\n");
			return bpf_redirect_map(&xsks_map, index, 0);
		}
    }
out:
	return stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
