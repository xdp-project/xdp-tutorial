/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "xsk_def_xdp_prog.h"

#define DEFAULT_QUEUE_IDS 64

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	/* Assignment#1: Add byte counters */
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

enum {
	k_tracing = 0,
	k_tracing_detail = 0
};

enum {
	k_hashmap_size = 64
};

//enum action_enum {
//	k_action_redirect ,
//	k_action_pass ,
//	k_action_drop
//}  ;
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct fivetuple {
	__u32 saddr ; // Source address (network byte order)
	__u32 daddr ; // Destination address (network byte order)
	__u16 sport ; // Source port (network byte order) use 0 for ICMP
	__u16 dport ; // Destination port (network byte order) use 0 for ICMP
	__u8 protocol ; // Protocol
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH) ;
	__uint(key_size, sizeof(struct fivetuple)) ;
	__uint(value_size, sizeof(enum xdp_action)) ;
	__uint(max_entries, k_hashmap_size) ;
} accept_map SEC(".maps");


struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

static __always_inline void display_one(int index) {
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	bpf_printk("xsks_map[%d]=%p\n", index, mapped) ;
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

#if 0
/* This is the supplied libxdp default program for post 5.3 kernels. */
SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
	/* A set entry here means that the corresponding queue_id
	 * has an active AF_XDP socket bound to it.
	 */
	if(k_tracing_detail) display_all() ;
    int index = ctx->rx_queue_index;
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if( k_tracing ) bpf_printk("xsks[%d]=%p\n", index, mapped) ;
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, int);
	__type(value, struct datarec);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats_map SEC(".maps");

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

static __always_inline int parse_tcp4hdr(struct hdr_cursor *nh,
		                        void *data_end,
					struct tcphdr **tcp4hdr)
{
	struct tcphdr *tcp4h = nh->pos;
	int hdrsize = sizeof(*tcp4h);
	if (nh->pos + hdrsize >data_end)
		return -1;
//	int actual_hdrsize = ip4h->ihl*4;
//	if (nh->pos + actual_hdrsize > data_end)
//		return -1;
	int actual_hdrsize=hdrsize ; // Ignore the possibility of TCP options
	nh->pos += actual_hdrsize;
	*tcp4hdr = tcp4h; /* Network byte order */
	return 0;
}


SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{

	if(k_tracing_detail) display_all() ;
    int index = ctx->rx_queue_index;
	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	void * mapped=bpf_map_lookup_elem(&xsks_map, &index) ;
	if( k_tracing ) bpf_printk("xsks_map[%d]=%p\n", index, mapped) ;

    enum xdp_action action = XDP_PASS; /* Default action */
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

				struct fivetuple f ;
				f.protocol = IPPROTO_UDP ;
				f.saddr = iphdr->saddr ;
				f.daddr = iphdr->daddr ;
				if ( protocol == IPPROTO_TCP ) {
					struct tcphdr *t ;
					rc = parse_tcp4hdr(&nh, data_end, &t);
					if (rc != 0) goto out ;
//					struct tcphdr *t= (struct tcphdr *)(iphdr+1) ;
					f.sport = t->source ;
					f.dport = t->dest ;
					void * v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
					action = *(enum xdp_action *) v_permit ;
				} else if ( protocol == IPPROTO_UDP ) {
					struct udphdr *u ;
					rc = parse_udp4hdr(&nh, data_end, &u);
					if (rc != 0) goto out ;
//					struct udphdr *u = (struct udphdr *)(iphdr+1) ;
					f.sport = u->source ;
					f.dport = u->dest ;
					void * v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
					action = *(enum xdp_action *) v_permit ;
				} else if ( protocol == IPPROTO_ICMP ) {
					f.sport = 0 ;
					f.dport = 0 ;
					void * v_permit=bpf_map_lookup_elem(&accept_map, &f) ;
					action = *(enum xdp_action *) v_permit ;
				}
			}

		if ( action == XDP_REDIRECT) {
			stats_record_action(ctx, XDP_REDIRECT);
			if( k_tracing ) bpf_printk("returning through bpf_redirect_map\n");
			return bpf_redirect_map(&xsks_map, index, 0);
		}
    }
out:
	return stats_record_action(ctx, action); /* read via xdp_stats */
}


char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
