/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"


/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr eth_cpy;
        struct vlan_hdr *vlh;
        __be16 h_proto;
        int vlid;

        if (!proto_is_vlan(eth->h_proto))
                return -1;

        /* Careful with the parenthesis here */
        vlh = (void *)(eth + 1);

        /* Still need to do bounds checking */
        if (vlh + 1 > data_end)
                return -1;

        /* Save vlan ID for returning, h_proto for updating Ethernet header */
        vlid = bpf_ntohs(vlh->h_vlan_TCI);
        h_proto = vlh->h_vlan_encapsulated_proto;

        /* Make a copy of the outer Ethernet header before we cut it off */
        __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

        /* Actually adjust the head pointer */
        if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
                return -1;

        /* Need to re-evaluate data *and* data_end and do new bounds checking
         * after adjusting head
         */
        eth = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        if (eth + 1 > data_end)
                return -1;

        /* Copy back the old Ethernet header and update the proto type */
        __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
        eth->h_proto = h_proto;

        return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
                                         struct ethhdr *eth, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr eth_cpy;
        struct vlan_hdr *vlh;

        /* First copy the original Ethernet header */
        __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

        /* Then add space in front of the packet */
        if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
                return -1;

        /* Need to re-evaluate data_end and data after head adjustment, and
         * bounds check, even though we know there is enough space (as we
         * increased it).
         */
        data_end = (void *)(long)ctx->data_end;
        eth = (void *)(long)ctx->data;

        if (eth + 1 > data_end)
                return -1;

        /* Copy back the Ethernet header in the right place, populate the VLAN
         * tag with the ID and proto, and set the outer Ethernet header to VLAN
         * type. */
        __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

        vlh = (void *)(eth +1);

        if (vlh + 1 > data_end)
                return -1;

        vlh->h_vlan_TCI = bpf_htons(vlid);
        vlh->h_vlan_encapsulated_proto = eth->h_proto;

        eth->h_proto = bpf_htons(ETH_P_8021Q);
        return 0;
}

/* Solution to the assignments in lesson packet02: Will pop outermost VLAN tag
 * if it exists, otherwise push a new one with ID 1
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
        nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
        if (nh_type < 0)
                return XDP_PASS;

        if (proto_is_vlan(eth->h_proto))
                vlan_tag_pop(ctx, eth);
        else
                vlan_tag_push(ctx, eth, 1);

        return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
