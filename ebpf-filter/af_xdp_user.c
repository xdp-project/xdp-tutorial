/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define INSTRUMENT 0
#define VERIFY_UMEM 0

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

enum {
	k_rx_queue_count = 16 ,
	k_skipping = false
};

struct xsk_umem_info {
//	struct xsk_ring_prod fq;
//	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
	uint64_t umem_frame_addr[NUM_FRAMES*2];
	uint32_t umem_frame_free;

	uint64_t allocation_count;
	uint64_t free_count;
#if VERIFY_UMEM == 1
	char *mark_buffer;
#endif
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_outofsequence;
	uint64_t rx_duplicate;
	uint64_t rx_batch_count;
	uint64_t filter_passes[256] ;
	uint64_t filter_drops[256] ;
};

struct transfer_state {
	uint64_t udp_packet_count ;
};
struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem_info umem;
	struct xsk_socket *xsk;

//	uint32_t outstanding_tx;

};

struct all_socket_info {
	struct xsk_socket_info *xsk_socket_info[k_rx_queue_count] ;
};

struct socket_stats {
	struct stats_record stats;
	struct stats_record prev_stats;
	struct transfer_state trans;
	uint8_t prev_sequence;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",	 required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{"progsec_1",	 required_argument,	NULL,  3  },
	 "Load program 1 in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

enum {
	k_bytesperline = 16
};
static void hexdump1(FILE *out, const unsigned char *data, unsigned long offset, unsigned long length)
{
	fprintf(out, "\n0x%04lx", offset ) ;
	for(int a=0; a<length; a+=1) fprintf(out, " %02x", data[offset+a]) ;
}
static void hexdump(FILE *out, const void *data, unsigned long length)
{
	const unsigned char * cdata = data ;
	unsigned long fullcount=length / k_bytesperline ;
	unsigned int tailcount=length % k_bytesperline ;
	for(unsigned long i=0; i<fullcount; i+=1 ) {
		hexdump1(out, cdata, (i*k_bytesperline), k_bytesperline) ;
	}
	if ( tailcount > 0 ) hexdump1(out, cdata, (fullcount*k_bytesperline), tailcount) ;
	fprintf(out, "\n") ;
}
static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(struct xsk_umem_info *umem,
		                                        void *buffer,
												uint64_t size,
												struct xsk_ring_prod *fq,
												struct xsk_ring_cons *cq)
{
//	struct xsk_umem_info *umem;
	int ret;
	int i;

//	umem = calloc(1, sizeof(*umem));
//	if (!umem)
//		return NULL;

//	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
//			       NULL);
	ret = xsk_umem__create(&umem->umem, buffer, size, fq, cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
#if VERIFY_UMEM == 1
	umem->mark_buffer = calloc(size,1) ;
#endif
	/* Initialize umem frame allocation */

	for (i = 0; i < 2*NUM_FRAMES; i++)
		umem->umem_frame_addr[i] = i * FRAME_SIZE;

	umem->umem_frame_free = 2*NUM_FRAMES;
	return umem;
}

static uint64_t umem_alloc_umem_frame(struct xsk_umem_info *umem)
{
	uint64_t frame;
	assert(umem->umem_frame_free > 0);
	if (umem->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = umem->umem_frame_addr[--umem->umem_frame_free];
#if VERIFY_UMEM == 1
	uint64_t aligned_frame=frame & ~(FRAME_SIZE-1) ;
	assert(umem->mark_buffer[aligned_frame] == 0) ;
	umem->mark_buffer[aligned_frame] = 1;
#endif
	umem->umem_frame_addr[umem->umem_frame_free] = INVALID_UMEM_FRAME;
	umem->allocation_count += 1;
	if(INSTRUMENT) printf("umem_alloc_umem_frame umem=%p allocation_count=%ld free_count=%ld frame=0x%lx\n", umem, umem->allocation_count, umem->free_count, frame) ;
	return frame;
}

static void umem_free_umem_frame(struct xsk_umem_info *umem, uint64_t frame)
{
	if(INSTRUMENT) printf("xsk_free_umem_frame xsk=%p allocation_count=%ld free_count=%ld frame=0x%lx\n", umem, umem->allocation_count,umem->free_count,frame);
#if VERIFY_UMEM == 1
	uint64_t aligned_frame=frame & ~(FRAME_SIZE-1) ;
	assert(umem->mark_buffer[aligned_frame] == 1);
	umem->mark_buffer[aligned_frame] = 0;
#endif
	assert(umem->umem_frame_free < 2*NUM_FRAMES);

	umem->umem_frame_addr[umem->umem_frame_free++] = frame;
	umem->free_count += 1;
}

static uint64_t xsk_umem_free_frames(struct xsk_umem_info *umem)
{
	return umem->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
//						    struct xsk_umem_info *umem,
//							struct xsk_ring_prod *fq,
//							struct xsk_ring_cons *cq,
							int if_queue)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	int packet_buffer_size = NUM_FRAMES * FRAME_SIZE * 2;
	void *packet_buffer;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	configure_xsk_umem(&(xsk_info->umem),
			           packet_buffer,
					   packet_buffer_size,
					   &(xsk_info->fq), &(xsk_info->cq));
//	if (xsk_info->umem == NULL) {
//		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
//			strerror(errno));
//		exit(EXIT_FAILURE);
//	}
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
//	xsk_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.libxdp_flags = 0;
	ret = xsk_socket__create_shared(&xsk_info->xsk,
			                 cfg->ifname,
			                 if_queue,
							 xsk_info->umem.umem,
							 &xsk_info->rx,
				             &xsk_info->tx,
							 &(xsk_info->fq),
							 &(xsk_info->cq),
							 &xsk_cfg);

//	ret = xsk_socket__create(&xsk_info->xsk,
//			                 cfg->ifname,
//				              if_queue,
//							  umem->umem,
//							  &xsk_info->rx,
//				              &xsk_info->tx,
//							  &xsk_cfg);
	printf("xsk_socket__create returns %d\n", ret) ;
	if (ret)
		goto error_exit;

//	ret = xsk_setup_xdp_prog(
//			slot == 0 ? cfg->ifindex : cfg->redirect_ifindex,
//					NULL) ;
//	printf("xsk_setup_xdp_prog returns %d\n", ret) ;
//	if (ret)
//		goto error_exit;


////	ret = bpf_get_link_xdp_id(slot == 0 ? cfg->ifindex : cfg->redirect_ifindex, &prog_id, cfg->xdp_flags);
//	ret = bpf_xdp_query_id(slot == 0 ? cfg->ifindex : cfg->redirect_ifindex, cfg->xdp_flags, &prog_id);
//	if (ret)
//		goto error_exit;

	/* Stuff the receive path with buffers, we assume we have enough */
	__u32 idx;
	ret = xsk_ring_prod__reserve(&xsk_info->fq,
					 XSK_RING_PROD__DEFAULT_NUM_DESCS,
					 &idx);

	printf("xsk_ring_prod__reserve returns %d, XSK_RING_PROD__DEFAULT_NUM_DESCS is %d\n", ret, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->fq, idx++) =
			umem_alloc_umem_frame(&xsk_info->umem);

	xsk_ring_prod__submit(&xsk_info->fq,
				  XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static struct all_socket_info *xsk_configure_socket_all(struct config *cfg)
{

//	uint32_t idx;
//	int ret=0;
	struct all_socket_info *xsk_info_all = calloc(1, sizeof(*xsk_info_all));
	for(int q=0; q<k_rx_queue_count; q+=1)
	{
		xsk_info_all->xsk_socket_info[q]=xsk_configure_socket(cfg, q);
		if(xsk_info_all->xsk_socket_info[q] == NULL )
		{
			fprintf(stderr, "ERROR: Cannot set up socket %d\n", q) ;
			return NULL ;
		}
	}
	return xsk_info_all;
}
//static void complete_tx(struct xsk_socket_info *xsk,
//		struct xsk_socket_info *xsk_src,
//		struct xsk_ring_prod *fq,
//		struct xsk_ring_cons *cq
//		)
//{
//	unsigned int completed;
//	uint32_t idx_cq;
//
//	if (!xsk->outstanding_tx)
//		return;
//
//	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
//
//
//	/* Collect/free completed TX buffers */
//	completed = xsk_ring_cons__peek(cq,
//					XSK_RING_CONS__DEFAULT_NUM_DESCS,
//					&idx_cq);
//
//	assert(completed <= xsk->outstanding_tx) ;
//	if (completed > 0) {
//		for (int i = 0; i < completed; i++)
//			umem_free_umem_frame(xsk->umem,
//					    *xsk_ring_cons__comp_addr(cq,
//								      idx_cq++));
//
//		xsk_ring_cons__release(cq, completed);
//		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
//			completed : xsk->outstanding_tx;
//	}
//}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

//static bool skipsend(struct transfer_state *trans)
//{
//	trans->udp_packet_count += 1 ;
//	if (trans->udp_packet_count < 10 ) return false ;
//	return true;
////	return (trans->udp_packet_count & 1) ? true : false ;
//}

static bool filter_pass(__u32 saddr, __u32 daddr, __u8 protocol, __u16 sport, __u16 dport) {
	return true ;
}
static bool process_packet(struct xsk_socket_info *xsk_src,
			   uint64_t addr, uint32_t len,
			   struct socket_stats *stats,
			   int tun_fd)
{
	uint8_t *pkt = xsk_umem__get_data(xsk_src->umem.buffer, addr);

        /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	if (true) {
//		int ret;
//		uint32_t tx_idx = 0;
//		uint64_t tx_frame;
//		uint8_t tmp_mac[ETH_ALEN];
//		struct in6_addr tmp_ip;
		struct ethhdr *eth = (struct ethhdr *) pkt;
		struct iphdr *ip = (struct iphdr *) (eth + 1);
//		struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);
//
//		struct iphdr {
//		#if defined(__LITTLE_ENDIAN_BITFIELD)
//			__u8	ihl:4,
//				version:4;
//		#elif defined (__BIG_ENDIAN_BITFIELD)
//			__u8	version:4,
//		  		ihl:4;
//		#else
//		#error	"Please fix <asm/byteorder.h>"
//		#endif
//			__u8	tos;
//			__be16	tot_len;
//			__be16	id;
//			__be16	frag_off;
//			__u8	ttl;
//			__u8	protocol;
//			__sum16	check;
//			__be32	saddr;
//			__be32	daddr;
//			/*The options start here. */
//		};
		if (ntohs(eth->h_proto) == ETH_P_IP &&
		    len > (sizeof(*eth) + sizeof(*ip))) {
			hexdump(stdout, ip, (len < 32) ? len : 32) ;
			fprintf(stdout, "iphdr ihl=0x%01x version=0x%01x tos=0x%02x "
					"tot_len=0x%04x id=0x%04x flags=0x%02x frag_off=0x%04x ttl=0x%02x "
					"protocol=0x%02x check=0x%04x saddr=0x%08x daddr=0x%08x",
					ip->ihl, ip->version, ip->tos, ntohs(ip->tot_len),
					ntohs(ip->id),ntohs(ip->frag_off) >> 13,
					ntohs(ip->frag_off) & 0x1fff, ip->ttl,ip->protocol,
					ip->check, ntohl(ip->saddr), ntohl(ip->daddr));
			__u8 protocol=ip->protocol;
			__u32 saddr=ntohl(ip->saddr) ;
			__u32 daddr=ntohl(ip->daddr) ;

			struct tcphdr *tcp = (struct tcphdr *) (ip + 1);
//			struct tcphdr {
//				__be16	source;
//				__be16	dest;
			__u32 sourceport=ntohs(tcp->source);
			__u32 destport=ntohs(tcp->dest) ;
//			fprintf(stdout, "saddr=0x%08x daddr=0x%08x protocol=0x%02x\n",
//					saddr, daddr) ;
			if (filter_pass(saddr, daddr, protocol, sourceport, destport ))
			{
				stats->stats.filter_passes[protocol] += 1;
				uint8_t *write_addr=pkt+sizeof(struct ethhdr);
				size_t write_len=len-sizeof(struct ethhdr);
				ssize_t ret=write(tun_fd,  write_addr, write_len) ;
				hexdump(stdout, write_addr, (write_len < 32) ? write_len : 32) ;
                fprintf(stdout, "Write length %lu actual %ld\n", write_len, ret) ;
				if ( ret != write_len ) {
					fprintf(stderr, "Error. %lu bytes requested, %ld bytes delivered, errno=%d %s\n",
							write_len, ret, errno, strerror(errno)) ;
					exit(EXIT_FAILURE);
				}
			} else {
				stats->stats.filter_drops[protocol] += 1;
			}
		}
		return false ; // Not transmitting anything
	}

	return false;
}

static void handle_receive_packets(
		struct xsk_socket_info *xsk_src,
		struct socket_stats *stats,
		int tun_fd)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk_src->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk_src->fq,
					xsk_umem_free_frames(&xsk_src->umem));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk_src->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk_src->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk_src->fq, idx_fq++) =
				umem_alloc_umem_frame(&xsk_src->umem);

		xsk_ring_prod__submit(&xsk_src->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk_src->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk_src->rx, idx_rx++)->len;

		bool transmitted=process_packet(xsk_src, addr, len, stats, tun_fd) ;

		if(INSTRUMENT) printf("addr=0x%lx len=%u transmitted=%u\n", addr, len, transmitted);
		if (!transmitted)
			umem_free_umem_frame(&xsk_src->umem, addr);

		stats->stats.rx_bytes += len;
		stats->stats.rx_packets += 1;
	}

	stats->stats.rx_batch_count += 1;
	xsk_ring_cons__release(&xsk_src->rx, rcvd);

  }

static void rx_and_process(struct config *cfg,
			   struct all_socket_info *all_socket_info,
			   struct socket_stats *stats,
			   int tun_fd)
{
	struct pollfd fds[k_rx_queue_count];
	int ret, nfds = k_rx_queue_count;

	memset(fds, 0, sizeof(fds));
	for(int q=0; q<k_rx_queue_count; q+=1) {
		fds[q].fd = xsk_socket__fd(all_socket_info->xsk_socket_info[q]->xsk);
		fds[q].events = POLLIN;
	}

	while(!global_exit) {
//		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > k_rx_queue_count)
				continue;
//		}
//			if(INSTRUMENT) {
//				printf("rx_and_process xsk_0=%p fds[0].revents=0x%x\n", xsk_socket_0, fds[0].revents);
//			}
		for(int q=0; q<k_rx_queue_count; q+=1) {
			if ( fds[q].revents & POLLIN ) handle_receive_packets(all_socket_info->xsk_socket_info[q], stats, tun_fd) ;
		}
//		handle_receive_packets(xsk_socket);
	}
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
	    " %lu dups %lu out of seqs %lu batches"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	       stats_rec->rx_bytes / 1000 , bps,
		   stats_rec->rx_duplicate,
		   stats_rec->rx_outofsequence,
		   stats_rec->rx_batch_count,
	       period);

//	packets = stats_rec->tx_packets - stats_prev->tx_packets;
//	pps     = packets / period;
//
//	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
//	bps     = (bytes * 8) / period / 1000000;
//
//	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
//	       stats_rec->tx_bytes / 1000 , bps,
//		   0,
//		   0,
//		   0,
//	       period);

	for(int proto=0; proto < 256; proto += 1) {
		uint64_t passes=stats_rec->filter_passes[proto] ;
		uint64_t drops=stats_rec->filter_drops[proto] ;
		if (passes+drops > 0) {
			printf("passes[%d]=%lu drops[%d]=%lu total[%d]=%lu",
					proto, passes, proto, drops, proto, passes+drops);
		}
	}
	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct socket_stats *stats = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		stats->stats.timestamp = gettime();
		stats_print(&(stats->stats), &previous_stats);
		stats->prev_stats = stats->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int tun_alloc(char *dev)
  {
      struct ifreq ifr;
      int fd, err;

      if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
         return fd;

      memset(&ifr, 0, sizeof(ifr));

      /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
       *        IFF_TAP   - TAP device
       *
       *        IFF_NO_PI - Do not provide packet information
       */
      ifr.ifr_flags = IFF_TUN ;
      if( *dev )
         strncpy(ifr.ifr_name, dev, IFNAMSIZ);

      if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
         close(fd);
         return err;
      }
      strcpy(dev, ifr.ifr_name);
      return fd;
  }

int main(int argc, char **argv)
{
	int ret;
//	int xsks_map_fd;
//	void *packet_buffer;
//	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex = -1,
		.do_unload = false,
		.filename = "",
		.progsec = "xdp_sock_0",
		.progsec_1 = "xdp_sock_1"
	};
//	struct xsk_umem_info *umem;
	struct all_socket_info *all_socket_info;
//	struct bpf_object *bpf_obj = NULL;
//	struct bpf_program *bpf_prog ;
	struct xdp_program *xdp_prog ;
//	int prog_fd ;
	int err;
	pthread_t stats_poll_thread;
	struct socket_stats stats;
	int tun_fd ;
	char tun_name[IFNAMSIZ] ;

	memset(&stats, 0, sizeof(stats));

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload) {
////		struct bpf_xdp_attach_opts attach_opts = {
////				sz : 0,
////				old_prog_fd : 0
////		};
//		LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts, .old_prog_fd=0) ;
//		int err_0=bpf_xdp_detach(cfg.ifindex, 0, &attach_opts);
		int err_0=0;
		return err_0;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
//		struct bpf_map *map;

////		bpf_obj = load_bpf_and_xdp_attach(&cfg);
//		bpf_obj = bpf_object__open_file(cfg.filename, NULL);
//		if (!bpf_obj) {
//			/* Error handling done in load_bpf_and_xdp_attach() */
//			exit(EXIT_FAILURE);
//		}
////		if (cfg.progsec[0])
////			/* Find a matching BPF prog section name */
////			bpf_prog = bpf_object__find_program_by_name(bpf_obj, cfg.progsec);
////		else
//			/* Find the first program */
//			bpf_prog = bpf_object__next_program(bpf_obj, NULL);
////			bpf_prog = NULL ;
//
//		if (!bpf_prog) {
//			fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg.progsec);
//			exit(EXIT_FAIL_BPF);
//		}
//		bpf_program__set_type(bpf_prog,BPF_PROG_TYPE_XDP) ;
//
//		int ret=bpf_object__load(bpf_obj) ;
//		if ( ret < 0 )
//		{
//			fprintf(stderr, "ERROR: bpf_object__load fails: %s\n",
//							strerror(ret));
//		}
////			strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));
//
//		prog_fd = bpf_program__fd(bpf_prog);
//		if (prog_fd <= 0) {
//			fprintf(stderr, "ERR: bpf_program__fd failed\n");
//			exit(EXIT_FAIL_BPF);
//		}
//
//		/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
//		 * is our select file-descriptor handle. Next step is attaching this FD
//		 * to a kernel hook point, in this case XDP net_device link-level hook.
//		 */
////		struct bpf_xdp_attach_opts attach_opts = {
////				sz : 0,
////				old_prog_fd: 0
////		};
//		LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts, .old_prog_fd=0) ;
//		err = bpf_xdp_attach(cfg.ifindex, prog_fd, 0, &attach_opts);
//		if (err)
//		{
//			fprintf(stderr, "ERROR:bpf_xdp_attach returns %d\n", err) ;
//			exit(EXIT_FAILURE);
//		}
//
//		/* We also need to load the xsks_map */
//		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
//		if ( map == NULL ) {
//			fprintf(stderr, "ERROR:bpf_object__find_map_by_name returns NULL for xsks_map\n") ;
//			exit(EXIT_FAILURE);
//		}
//		xsks_map_fd = bpf_map__fd(map);
//		if (xsks_map_fd < 0) {
//			fprintf(stderr, "ERROR: no xsks map found: %s\n",
//				strerror(xsks_map_fd));
//			exit(EXIT_FAILURE);
//		}
		fprintf(stderr,"Opening program file %s\n", cfg.filename) ;
		xdp_prog=xdp_program__open_file(cfg.filename,NULL, NULL)  ;
		fprintf(stderr,"xdp_prog=%p\n", xdp_prog) ;
		err=xdp_program__attach(xdp_prog,
				cfg.ifindex, XDP_MODE_SKB, 0);
		if (err)
		{
			fprintf(stderr, "ERROR:xdp_program__attach returns %d\n", err) ;
			exit(EXIT_FAILURE);
		}

	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
//
//	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
//	packet_buffer_size = NUM_FRAMES * FRAME_SIZE * 2;
//	if (posix_memalign(&packet_buffer,
//			   getpagesize(), /* PAGE_SIZE aligned */
//			   packet_buffer_size)) {
//		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
//			strerror(errno));
//		exit(EXIT_FAILURE);
//	}

//	/* Initialize shared packet_buffer for umem usage */
//	struct xsk_ring_prod fq ;
//	struct xsk_ring_cons cq ;
//	memset(&fq,0,sizeof(fq));
//	memset(&cq,0,sizeof(cq));
//	umem = configure_xsk_umem(packet_buffer, packet_buffer_size, &fq, &cq);
//	if (umem == NULL) {
//		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
//			strerror(errno));
//		exit(EXIT_FAILURE);
//	}

	/* Open and configure the AF_XDP (xsk) socket */
	all_socket_info = xsk_configure_socket_all(&cfg);
	if (all_socket_info == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP sockets \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Set up xsks map
	err=xsk_setup_xdp_prog(cfg.ifindex, NULL);
	if (err)
	{
		fprintf(stderr, "ERROR:xsk_setup_xdp_prog returns %d\n", err) ;
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (verbose && 0 == INSTRUMENT) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     &stats);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Start TAP */
	strcpy(tun_name, "tun0");
	tun_fd = tun_alloc(tun_name) ;
	if(tun_fd < 0) {
		err = errno ;
		fprintf(stderr, "ERROR:tun_alloc gives errno=%d %s\n", err, strerror(err)) ;
		exit(EXIT_FAILURE);
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, all_socket_info, &stats, tun_fd);

	/* Cleanup */
	close(tun_fd) ;
	for(int q=0; q<k_rx_queue_count; q += 1) {
		xsk_socket__delete(all_socket_info->xsk_socket_info[q]->xsk) ;
	}
//	xsk_umem__delete(umem->umem);
//	struct bpf_xdp_attach_opts attach_opts = {
//			sz : 0,
//			old_prog_fd : 0
//	};
//	LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts, .old_prog_fd=-1) ;
//	bpf_xdp_detach(cfg.ifindex, 0, &attach_opts);
	xdp_program__detach(xdp_prog, cfg.ifindex, XDP_MODE_SKB, 0);
	xdp_program__close(xdp_prog) ;

	return EXIT_OK;
}
