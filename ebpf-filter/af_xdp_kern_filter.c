/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h" /* defines: struct datarec; */

enum {
	k_tracing = 1
};
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

static __always_inline
__u32 stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if( k_tracing ) bpf_printk("stats_record_action action=%d\n", action);

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

	return action;
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


static __always_inline void display_one(int index) {
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
//	if(mapped != NULL) {
		bpf_printk("index%d mapped=%p\n", index, mapped) ;
//	}
}

static __always_inline void display_all(void) {
	display_one(0) ;
	display_one(1) ;
	display_one(2) ;
	display_one(3) ;
	display_one(4) ;
	display_one(5) ;
	display_one(6) ;
	display_one(7) ;
	display_one(8) ;
	display_one(9) ;
	display_one(10) ;
	display_one(11) ;
	display_one(12) ;
	display_one(13) ;
	display_one(14) ;
	display_one(15) ;
	display_one(16) ;
	display_one(17) ;
	display_one(18) ;
	display_one(19) ;
	display_one(20) ;
	display_one(21) ;
	display_one(22) ;
	display_one(23) ;
	display_one(24) ;
	display_one(25) ;
	display_one(16) ;
	display_one(27) ;
	display_one(28) ;
	display_one(29) ;
	display_one(30) ;
	display_one(31) ;
	display_one(32) ;
	display_one(33) ;
	display_one(34) ;
	display_one(35) ;
	display_one(36) ;
	display_one(37) ;
	display_one(38) ;
	display_one(39) ;
	display_one(40) ;
	display_one(41) ;
	display_one(42) ;
	display_one(43) ;
	display_one(44) ;
	display_one(45) ;
	display_one(46) ;
	display_one(47) ;
	display_one(48) ;
	display_one(49) ;
	display_one(50) ;
	display_one(51) ;
	display_one(52) ;
	display_one(53) ;
	display_one(54) ;
	display_one(55) ;
	display_one(56) ;
	display_one(57) ;
	display_one(58) ;
	display_one(59) ;
	display_one(60) ;
	display_one(61) ;
	display_one(62) ;
	display_one(63) ;
}
//static long display_loop(__u32 index, void *vctx)
//{
//	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
//	if(mapped != NULL) {
//		bpf_printk("index%d mapped=%p\n", index, mapped) ;
//	}
//	return 0;
//}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{

	display_all() ;
    int index = ctx->rx_queue_index;
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if( k_tracing ) bpf_printk("index=%d mapped=%p\n", index, mapped) ;

    __u32 action = XDP_PASS; /* Default action */
    if (mapped)
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
		if( k_tracing ) bpf_printk("nh_type=0x%04x ETH_P_IP=0x%04x\n", nh_type, ETH_P_IP);
		if (nh_type == bpf_htons(ETH_P_IP))
			{
						/* Assignment additions go below here */
				struct iphdr *iphdr;
				int rc;
				rc = parse_ip4hdr(&nh, data_end, &iphdr);
				if (rc != 0) goto out ;

				int protocol=iphdr->protocol;
				if( k_tracing ) bpf_printk("protocol=%d\n", protocol) ;
				if ( protocol == IPPROTO_UDP ) {
					action = XDP_DROP ;
					goto out;
				}

			}

		if( k_tracing ) bpf_printk("returning through bpf_redirect_map\n");
		return bpf_redirect_map(&xsks_map, index, 0);
    }
out:
	return stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
