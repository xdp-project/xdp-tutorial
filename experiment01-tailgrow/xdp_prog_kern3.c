/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* This is a barrier_var() operation that makes specified variable
 * "a black box" for optimizing compiler.
 */
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

/*
 * General idea: Use packet length to find and access last byte.
 */

SEC("xdp_works1")
int _xdp_works1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	/* Important to understand that data_end points to the byte AFTER
	 * the data 'where-data-ends' (e.g one byte off the end).  This is
	 * practical to calculate the length when subtracting two pointers.
	 */
	unsigned int offset = data_end - data;

	/* The offset now contains the byte length, but instead we want an
	 * offset (from data pointer) that point to the last byte in the
	 * packet. Thus, subtract one byte, but we need to stop compiler
	 * from optimzing this (else BPF verifier will reject).
	 */
	barrier_var(offset);
	offset = offset - 1;

	offset &= 0x7FFF; /* Bound/limit max value to help verifier */

	/* Explicitly use a position pointer (corresponding to data) being
	 * moved forward, to show how verifier tracks this.
	 */
	pos = data;
	pos += offset;

	/* BPF verifier needs this step: It show that reading one byte via
	 * position pointer 'pos' is safe.
	 */
	if (pos + 1 > data_end)
		return XDP_DROP;

	/* Access data in byte-steps via an unsigned char pointer */
	ptr = pos;
	if (*ptr == 0xFF) /* Reads last byte before data_end */
		return XDP_ABORTED;

	return XDP_PASS;
}
