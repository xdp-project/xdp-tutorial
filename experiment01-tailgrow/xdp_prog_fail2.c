/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * This BPF-prog will FAIL, due to verifier rejecting it.
 *
 * General idea: Use data_end point to access last (2nd-last) byte in
 * packet.  That is not allowed by verifier, as pointer arithmetic on
 * pkt_end is prohibited.
 */

SEC("xdp_fail2")
int _xdp_fail2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	volatile unsigned char *ptr;
	volatile void *pos;

	pos = data_end;

#pragma clang optimize off
	if (pos - 1 > data_end)
		goto out;
#pragma clang optimize on

	/* Verifier fails with: "pointer arithmetic on pkt_end prohibited"
	 */
	ptr = pos - 2;
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
