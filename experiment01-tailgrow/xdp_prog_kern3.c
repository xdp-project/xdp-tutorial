/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * This BPF-prog will drop all packets, but pass verifier checks.
 *
 * General idea: Use packet length to find and access last byte.
 */

SEC("xdp_fail1")
int _xdp_fail1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	unsigned int offset = data_end - data;

	pos = data;
	offset &= 0x7FFF; /* Bound/limit max value to help verifier */

	pos += offset;

	/* Below +1 will cause all packet to be dropped, as it will be
	 * longer than packet length (just calc as offset).
	 */
	if (pos + 1 > data_end)
		return XDP_DROP;

	ptr = pos;
	if (*ptr == 0xFF)
		return XDP_ABORTED;

	return XDP_PASS;
}
