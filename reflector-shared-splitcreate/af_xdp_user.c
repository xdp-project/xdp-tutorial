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

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>


#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#define INSTRUMENT 0
#define INSTRUMENT_STOCK 0

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
//	struct xsk_ring_prod fq;
//	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
	uint64_t allocation_count;
	uint64_t free_count;
	uint64_t umem_frame_addr[NUM_FRAMES*2];
	uint32_t umem_frame_free;

};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod *fq;
	struct xsk_ring_cons *cq;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
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

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size, struct xsk_ring_prod *fq, struct xsk_ring_cons *cq)
{
	struct xsk_umem_info *umem;
	int ret;
	int i;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

//	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
//			       NULL);
	ret = xsk_umem__create(&umem->umem, buffer, size, fq, cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES*2; i++)
		umem->umem_frame_addr[i] = i * FRAME_SIZE;

	umem->umem_frame_free = NUM_FRAMES*2;
	return umem;
}

static uint64_t umem_alloc_umem_frame(struct xsk_umem_info *umem)
{
	uint64_t frame;
	assert(umem->umem_frame_free > 0);
	if (umem->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = umem->umem_frame_addr[--umem->umem_frame_free];
	umem->umem_frame_addr[umem->umem_frame_free] = INVALID_UMEM_FRAME;
	umem->allocation_count += 1;
	if(INSTRUMENT) printf("umem_alloc_umem_frame umem=%p allocation_count=%ld free_count=%ld\n", umem, umem->allocation_count, umem->free_count) ;
	return frame;
}

static void umem_free_umem_frame(struct xsk_umem_info *umem, uint64_t frame)
{
	assert(umem->umem_frame_free < NUM_FRAMES*2);

	umem->umem_frame_addr[umem->umem_frame_free++] = frame;
	umem->free_count += 1;
	if(INSTRUMENT) printf("umem_free_umem_frame umem=%p allocation_count=%ld free_count=%ld\n", umem, umem->allocation_count,umem->free_count);
}

static uint64_t umem_free_frames(struct xsk_umem_info *umem)
{
	return umem->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem, int slot, struct xsk_ring_prod *fq, struct xsk_ring_cons *cq)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_info->fq = fq;
	xsk_info->cq = cq ;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	if ( slot == 0)
	{
		ret = xsk_socket__create(&xsk_info->xsk,
				cfg->ifname,
				cfg->xsk_if_queue,
				umem->umem,
				&xsk_info->rx,
				&xsk_info->tx,
				&xsk_cfg
				) ;
		printf("xsk_socket__create returns %d\n", ret) ;
	} else {

		ret = xsk_socket__create_shared(&xsk_info->xsk,
								 cfg->redirect_ifname,
								 cfg->xsk_if_queue,
								 umem->umem,
								 &xsk_info->rx,
								 &xsk_info->tx,
								 xsk_info->fq,
								 xsk_info->cq,
								 &xsk_cfg);

		printf("xsk_socket__create_shared returns %d\n", ret) ;
	}
	if (ret)
		goto error_exit;

	ret = bpf_get_link_xdp_id(slot == 0 ? cfg->ifindex : cfg->redirect_ifindex, &prog_id, cfg->xdp_flags);
	if (ret)
		goto error_exit;


//	if (slot == 0)
	{
		struct xsk_ring_prod * active_fq=fq ;
		/* Stuff the receive path with buffers, we assume we have enough */
		ret = xsk_ring_prod__reserve(active_fq,
						 XSK_RING_PROD__DEFAULT_NUM_DESCS,
						 &idx);

		printf("xsk_ring_prod__reserve returns %d, XSK_RING_PROD__DEFAULT_NUM_DESCS is %d\n", ret, XSK_RING_PROD__DEFAULT_NUM_DESCS);
		if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
			goto error_exit;

		for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
			*xsk_ring_prod__fill_addr(active_fq, idx++) =
				umem_alloc_umem_frame(umem);

		xsk_ring_prod__submit(active_fq,
					  XSK_RING_PROD__DEFAULT_NUM_DESCS);
	}
	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk, struct xsk_socket_info *xsk_src)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(xsk->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if ( INSTRUMENT ) {
		printf("xsk=%p outstanding_tx=%u completed=%u\n", xsk, xsk->outstanding_tx, completed);
	}
	assert(completed <= xsk->outstanding_tx) ;
	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			umem_free_umem_frame(xsk->umem,
					    *xsk_ring_cons__comp_addr(xsk->cq,
								      idx_cq++));

		xsk_ring_cons__release(xsk->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

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

static bool process_packet(struct xsk_socket_info *xsk_dst, struct xsk_socket_info *xsk_src,
			   uint64_t addr, uint32_t len)
{
//	uint8_t *pkt = xsk_umem__get_data(xsk_src->umem->buffer, addr);

        /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	if (true) {
		int ret;
		uint32_t tx_idx = 0;
//		uint64_t tx_frame;
//		uint8_t tmp_mac[ETH_ALEN];
//		struct in6_addr tmp_ip;
//		struct ethhdr *eth = (struct ethhdr *) pkt;
//		struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
//		struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);
//
//		if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
//		    len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
//		    ipv6->nexthdr != IPPROTO_ICMPV6 ||
//		    icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
//			return false;
//
//		memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
//		memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
//		memcpy(eth->h_source, tmp_mac, ETH_ALEN);
//
//		memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
//		memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
//		memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));
//
//		icmp->icmp6_type = ICMPV6_ECHO_REPLY;
//
//		csum_replace2(&icmp->icmp6_cksum,
//			      htons(ICMPV6_ECHO_REQUEST << 8),
//			      htons(ICMPV6_ECHO_REPLY << 8));
//
//		/* Here we sent the packet out of the receive port. Note that
//		 * we allocate one entry and schedule it. Your design would be
//		 * faster if you do batch processing/transmission */

//		tx_frame = xsk_alloc_umem_frame(xsk_dst) ;
//		if ( tx_frame == INVALID_UMEM_FRAME ) {
//			/* No more transmit frames, drop the packet */
//			return false ;
//		}
		ret = xsk_ring_prod__reserve(&xsk_dst->tx, 1, &tx_idx);
		if (ret != 1) {
			/* No more transmit slots, drop the packet */
			return false;
		}
		struct xdp_desc *tx_desc=xsk_ring_prod__tx_desc(&xsk_dst->tx, tx_idx);
//		tx_desc->addr=tx_frame ;
		tx_desc->addr=addr ;
		tx_desc->len = len ;
//		memcpy(xsk_umem__get_data(xsk_dst->umem->buffer,tx_frame), pkt, len) ;
		xsk_ring_prod__submit(&xsk_dst->tx, 1) ;
//		xsk_free_umem_frame(xsk_src, addr) ;

//		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
//		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
//		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk_dst->outstanding_tx++;

		xsk_dst->stats.tx_bytes += len;
		xsk_dst->stats.tx_packets++;
		return true;
	}

	return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk_dst, struct xsk_socket_info *xsk_src)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk_src->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(xsk_src->fq,
					xsk_umem_free_frames(xsk_src));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(xsk_src->fq, stock_frames,
					     &idx_fq);

		if(INSTRUMENT_STOCK) {
			printf("xsk_src=%p fq=%p stock_frames=%u ret=%d free_frames=%lu\n", xsk_src, xsk_src->fq, stock_frames, ret, umem_free_frames(xsk_src->umem)) ;
		}
		assert(ret == stock_frames) ;
		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(xsk_src->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(xsk_src->fq, idx_fq++) =
				umem_alloc_umem_frame(xsk_src->umem);

		xsk_ring_prod__submit(xsk_src->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk_src->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk_src->rx, idx_rx++)->len;

		if (!process_packet(xsk_dst, xsk_src, addr, len))
			xsk_free_umem_frame(xsk_src, addr);

		xsk_src->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk_src->rx, rcvd);
	xsk_src->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk_dst, xsk_src);
//	complete_tx(xsk_src);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket_0, struct xsk_socket_info *xsk_socket_1)
{
	struct pollfd fds[2];
	int ret, nfds = 2;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket_0->xsk);
	fds[0].events = POLLIN;
	fds[1].fd = xsk_socket__fd(xsk_socket_1->xsk);
	fds[1].events = POLLIN;

	while(!global_exit) {
//		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 2)
				continue;
//		}
			if(INSTRUMENT) {
				printf("rx_and_process xsk_0=%p xsk_1=%p fds[0].revents=0x%x fds[1].revents=0x%x\n", xsk_socket_0, xsk_socket_1, fds[0].revents, fds[1].revents);
			}
		if ( fds[0].revents & POLLIN ) handle_receive_packets(xsk_socket_1, xsk_socket_0) ;
		if ( fds[1].revents & POLLIN ) handle_receive_packets(xsk_socket_0, xsk_socket_1) ;
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
	       period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	       stats_rec->tx_bytes / 1000 , bps,
	       period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	int ret;
	int xsks_map_0_fd, xsks_map_1_fd;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex = -1,
		.do_unload = false,
		.filename = "",
		.progsec = "xdp_sock_0",
		.progsec_1 = "xdp_sock_1"
	};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket_0;
	struct xsk_socket_info *xsk_socket_1;
	struct bpf_object *bpf_obj = NULL;
	pthread_t stats_poll_thread;

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

	if (cfg.redirect_ifindex == -1) {
		fprintf(stderr, "ERROR: Required option --redirect_dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Unload XDP program if requested */
	if (cfg.do_unload) {
		int err_0=xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		int err_1=xdp_link_detach(cfg.redirect_ifindex, cfg.xdp_flags, 0);
		return (err_0 != 0) ? err_0 : err_1;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
		struct bpf_map *map;

		bpf_obj = load_bpf_and_xdp_attach(&cfg);
		if (!bpf_obj) {
			/* Error handling done in load_bpf_and_xdp_attach() */
			exit(EXIT_FAILURE);
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map_0");
		xsks_map_0_fd = bpf_map__fd(map);
		if (xsks_map_0_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map 0 found: %s\n",
				strerror(xsks_map_0_fd));
			exit(EXIT_FAILURE);
		}
		map = bpf_object__find_map_by_name(bpf_obj, "xsks_map_1");
		xsks_map_1_fd = bpf_map__fd(map);
		if (xsks_map_1_fd < 0) {
			fprintf(stderr, "ERROR: no xsks map 1 found: %s\n",
				strerror(xsks_map_1_fd));
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

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE * 2;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	struct xsk_ring_prod fq_0 ;
	struct xsk_ring_cons cq_0 ;
	memset(&fq_0,0,sizeof(fq_0)) ;
	memset(&cq_0,0,sizeof(cq_0)) ;
	struct xsk_ring_prod fq_1 ;
	struct xsk_ring_cons cq_1 ;
	memset(&fq_1,0,sizeof(fq_1)) ;
	memset(&cq_1,0,sizeof(cq_1)) ;
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size, &fq_0, &cq_0);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket_0 = xsk_configure_socket(&cfg, umem, 0, &fq_0, &cq_0);
	if (xsk_socket_0 == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket 0 \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	xsk_socket_1 = xsk_configure_socket(&cfg, umem, 1, &fq_1, &cq_1);
	if (xsk_socket_1 == NULL) {
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket 1 \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
//	verbose = 0;
	if (verbose &&  0 == INSTRUMENT ) {
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
				     xsk_socket_0);
		if (ret) {
			fprintf(stderr, "ERROR: Failed creating statistics thread "
				"\"%s\"\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket_0, xsk_socket_1);

	/* Cleanup */
	xsk_socket__delete(xsk_socket_0->xsk);
	xsk_socket__delete(xsk_socket_1->xsk);
	xsk_umem__delete(umem->umem);
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	xdp_link_detach(cfg.redirect_ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}
