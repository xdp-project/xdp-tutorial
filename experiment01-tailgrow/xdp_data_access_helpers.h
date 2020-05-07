/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Authors of Cilium
 *
 * Code copied from cilium/bpf/include/bpf/ctx/xdp.h
 *  https://github.com/cilium/cilium/blob/master/bpf/include/bpf/ctx/xdp.h
 */

#ifndef _XDP_DATA_ACCESS_HELPERS_H_
#define _XDP_DATA_ACCESS_HELPERS_H_

/* This must be a mask and all offsets guaranteed to be less than that. */
//#define __CTX_OFF_MAX			0xff
#define __CTX_OFF_MAX			0x1fff

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef EINVAL
# define EINVAL	22
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline __maybe_unused int
xdp_load_bytes(struct xdp_md *ctx, __u64 off, void *to, const __u64 len)
{
	void *from;
	int ret;
	/* LLVM tends to generate code that verifier doesn't understand,
	 * so force it the way we want it in order to open up a range
	 * on the reg.
	 */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[from] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [from]"=r"(from)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}

static __always_inline __maybe_unused int
xdp_store_bytes(struct xdp_md *ctx, __u64 off, const void *from,
		const __u64 len, __u64 flags __maybe_unused)
{
	void *to;
	int ret;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[to] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [to]"=r"(to)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}

#define ctx_load_bytes			xdp_load_bytes
#define ctx_store_bytes			xdp_store_bytes

#endif /* _XDP_DATA_ACCESS_HELPERS_H_ */
