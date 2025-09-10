/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

SEC("tc")
int _fix_port_egress(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct hdr_cursor nh = { .pos = data };
	int eth_type, ip_type, ret = TC_ACT_OK;
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct ethhdr *eth;

	if (data + sizeof(*eth) > data_end)
		goto out;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		goto out;


	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0)
			goto out;

		udphdr->source = bpf_htons(bpf_ntohs(udphdr->source) + 1);
		udphdr->check += bpf_htons(-1);
		if (!udphdr->check)
			udphdr->check += bpf_htons(-1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0)
			goto out;

		tcphdr->source = bpf_htons(bpf_ntohs(tcphdr->source) + 1);
		tcphdr->check += bpf_htons(-1);
		if (!tcphdr->check)
			tcphdr->check += bpf_htons(-1);
	}

out:
	return ret;
}
char _license[] SEC("license") = "GPL";
