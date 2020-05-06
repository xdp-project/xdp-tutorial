/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MTU 1536
#define MIN_LEN 14

/*
 * This example show howto access packet last byte in XDP packet,
 * without parsing packet contents.
 *
 * It is not very effecient, as it advance the data pointer one-byte in a
 * loop until reaching data_end.  This is needed as the verifier only allows
 * accessing data via advancing the position of the data pointer. The bounded
 * loop with a max number of iterations allows the verifier to see the bound.
 */

SEC("xdp_end_loop")
int _xdp_end_loop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	unsigned char *ptr;
	unsigned int i;
	void *pos;

	/* Assume minimum length to reduce loops needed a bit */
	unsigned int offset = MIN_LEN;

	pos = data;

	/* Verifier can handle this bounded 'basic-loop' construct */
	for (i = 0; i < (MTU - MIN_LEN); i++ ) {
		if (pos + offset > data_end) {
			/* Promise verifier no access beyond data_end */
			goto out;
		}
		if (pos + offset == data_end) {
			/* Found data_end, exit for-loop and read data.
			 *
			 * It seems strange, that finding data_end via
			 * moving pos (data) pointer forward is needed.
			 * This is because pointer arithmetic on pkt_end is
			 * prohibited by verifer.
			 *
			 * In principle data_end points to byte that is not
			 * accessible. Thus, accessing last readable byte
			 * via (data_end - 1) is prohibited by verifer.
			 */
			goto read;
		}
		offset++;
	}
	/* Show verifier all other cases exit program */
	goto out;

read:
	ptr = pos + (offset - sizeof(*ptr)); /* Parentheses needed */
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
