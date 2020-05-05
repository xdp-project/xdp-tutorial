/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define MTU 1536
#define MIN_LEN 64

SEC("xdp_test1b")
int _xdp_test1b(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	unsigned char *ptr;
	unsigned int i;
	void *pos;

	unsigned int offset = MIN_LEN;

	pos = data;

	/* Verifier can handle this bounded basic-loop construct */
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
//	ptr = pos + (offset - );
//	ptr = pos + (offset - sizeof(*ptr) - 1);
	ptr = pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}


SEC("xdp_test1")
int _xdp_test1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	unsigned char *ptr;
	unsigned int i;
	void *pos;

	unsigned int offset = 64;

	pos = data;

	if (pos + 64 > data_end)
		goto out;

	for (i = 0; i < (1536-64); i++ ) {
		if (pos + offset > data_end) {
			goto out;
		}
		if (pos + offset == data_end) {
			goto read;
		}
		offset++;
	}
	goto out;

read:
//	ptr = pos + (offset - );
//	ptr = pos + (offset - sizeof(*ptr) - 1);
	ptr = pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}


SEC("xdp_test2")
int _xdp_test2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	unsigned char *ptr;

	unsigned int offset = 64;

	nh.pos = data;

	if (nh.pos + offset > data_end)
		goto out;

//	ptr = nh.pos + (offset - 1);
	ptr = nh.pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return xdp_stats_record_action(ctx, XDP_PASS);
}

/* Invalid:
SEC("xdp_test3")
int _xdp_test3(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	unsigned int offset = data_end - data;

	if (offset < 2)
		goto out;

	pos = data;

	if (pos + offset > data_end)
		goto out;

	ptr = pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
*/

/* Also invalid
SEC("xdp_test4")
int _xdp_test4(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	volatile unsigned char *ptr;
	volatile void *pos;

	pos = data_end;

#pragma clang optimize off
	if (pos - 1 > data_end)
		goto out;

	ptr = pos - 2;  //Err: "pointer arithmetic on pkt_end prohibited"
	if (*ptr == 0xFF)
		return XDP_ABORTED;
#pragma clang optimize on
out:
	return XDP_PASS;
}
*/


SEC("xdp_pass")
int xdp_pass_f1(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, XDP_PASS);
}

