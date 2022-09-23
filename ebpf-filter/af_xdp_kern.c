/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map_0 SEC(".maps") ;

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map_1 SEC(".maps") ;

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

SEC("xdp_sock_0")
int xdp_sock_prog_0(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 action = XDP_PASS; /* Default action */
    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map_0, &index))
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
		if (nh_type == bpf_htons(ETH_P_IP))
			{
						/* Assignment additions go below here */
				struct iphdr *iphdr;
				int rc;
				rc = parse_ip4hdr(&nh, data_end, &iphdr);
				if (rc != 0) goto out ;

				int protocol=iphdr->protocol;
				if ( protocol == IPPROTO_UDP ) {
					action = XDP_DROP ;
					goto out;
				}

			}

//        return bpf_redirect_map(&xsks_map_0, index, 0);
    }
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
