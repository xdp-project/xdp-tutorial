/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * This BPF-prog will FAIL, due to verifier rejecting it.
 *
 * General idea: Use packet length to find and access last byte in
 * packet.  The verifier cannot see this is safe, as it cannot deduce
 * the packet length at verification time.
 */

SEC("xdp_fail1")
int _xdp_fail1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	/* (Correct me if I'm wrong)
	 *
	 * The verifier cannot use this packet length calculation as
	 * part of its static analysis.  It chooses to use zero as the
	 * offset value static value.
	 */
	unsigned int offset = data_end - data;

	pos = data;

	if (pos + offset > data_end)
		goto out;

	/* Fails at this line with:
	 *   "invalid access to packet, off=-1 size=1, R1(id=2,off=0,r=0)"
	 *   "R1 offset is outside of the packet"
	 *
	 * Because verifer used offset==0 it thinks that we are trying
	 * to access (data - 1), which is not within [data,data_end)
	 */
	ptr = pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
