/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_stats1";

static const struct option long_options[] = {
	{"help",        no_argument,		NULL, 'h' },
	{"dev",         required_argument,	NULL, 'd' },
	{"skb-mode",    no_argument,		NULL, 'S' },
	{"native-mode", no_argument,		NULL, 'N' },
	{"auto-mode",   no_argument,		NULL, 'A' },
	{"force",       no_argument,		NULL, 'F' },
	{"unload",      no_argument,		NULL, 'U' },
	{"quiet",       no_argument,		NULL, 'q' },
	{"progsec",    required_argument,	NULL,  2  },
	{0, 0, NULL,  0 }
};

static void print_map_fd_info(int map_fd)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	if (map_fd < 0)
		return;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		exit(EXIT_FAIL_BPF) ;
	}
	if (verbose)
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s\n",
		       info.type, info.id, info.name);
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	int map_fd;

	map_fd = bpf_object__find_map_fd_by_name(bpf_obj, mapname);
        if (map_fd < 0) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
	}
	return map_fd;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats;
};

static double calc_period(struct record *r, struct record *p)
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
	struct record *rec, *prev;
	double period;
	__u64 packets;
	double pps;

	rec  = &stats_rec->stats;
	prev = &stats_prev->stats;

	period = calc_period(rec, prev);
	if (period == 0)
		return;

	packets = rec->total.rx_packets - prev->total.rx_packets;
	pps     = packets / period;

	printf("XDP stats: %-7s RX-pkts:%'-10lld pps:%'-11.0f period:%f\n",
	       "total", packets, pps, period);
}

static bool map_collect(int fd, __u32 key, struct record *rec)
{
	struct datarec value;

	if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return false;
	}
	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	rec->total.rx_packets = value.rx_packets;
	return true;
}

static void stats_collect(int map_fd, struct stats_record *stats_rec)
{
	map_collect(map_fd, 0, &stats_rec->stats);
}

static void stats_poll(int map_fd, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		print_map_fd_info(map_fd);
	}

	/* Get initial reading quickly */
	stats_collect(map_fd, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	int stats_map_fd;
	int interval = 2;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options);
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Lesson: Locate map file descriptor */
	stats_map_fd = find_map_fd(bpf_obj, "stats_array_map");
	if (stats_map_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	stats_poll(stats_map_fd, interval);

	return EXIT_OK;
}
