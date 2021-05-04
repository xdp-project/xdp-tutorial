/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <linux/err.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

#include <linux/perf_event.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/ioctl.h>

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

static const char *default_filename = "trace_prog_kern.o";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{0, 0, NULL,  0 }}
};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

static void stats_print(int map_fd)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__s32 key;
	void *keyp = &key, *prev_keyp = NULL;
	int err;

	while (true) {
		char dev[IF_NAMESIZE];
		__u64 total = 0;
		int i;

		err = bpf_map_get_next_key(map_fd, prev_keyp, keyp);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		if ((bpf_map_lookup_elem(map_fd, keyp, values)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
			continue;
		}

		/* Sum values from each CPU */
		for (i = 0; i < nr_cpus; i++)
			total += values[i];

		printf("%s (%llu) ", if_indextoname(key, dev), total);
		prev_keyp = keyp;
	}

	printf("\n");
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (1) {
		stats_print(map_fd);
		sleep(interval);
	}
}

/* Lesson#4: It is userspace responsibility to known what map it is reading and
 * know the value size. Here get bpf_map_info and check if it match our expected
 * values.
 */
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int filename__read_int(const char *filename, int *value)
{
	char line[64];
	int fd = open(filename, O_RDONLY), err = -1;

	if (fd < 0)
		return -1;

	if (read(fd, line, sizeof(line)) > 0) {
		*value = atoi(line);
		err = 0;
	}

	close(fd);
	return err;
}

#define TP "/sys/kernel/debug/tracing/events/"

static int read_tp_id(const char *name, int *id)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, TP "%s/id", name);
	return filename__read_int(path, id);
}

static inline int
sys_perf_event_open(struct perf_event_attr *attr,
		    pid_t pid, int cpu, int group_fd,
		    unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static struct bpf_object* load_bpf_and_trace_attach(struct config *cfg)
{
	struct perf_event_attr attr;
	struct bpf_object *obj;
	int err, bpf_fd;
	int id, fd;

	if (bpf_prog_load(cfg->filename, BPF_PROG_TYPE_TRACEPOINT, &obj, &bpf_fd)) {
		fprintf(stderr, "ERR: failed to load program\n");
		goto err;
	}

	if (read_tp_id("xdp/xdp_exception", &id)) {
		fprintf(stderr, "ERR: can't get program section\n");
		goto err;
	}

	/* Setup tracepoint perf event */
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.config = id;
	attr.sample_period = 1;

	/* .. and open it */
	fd = sys_perf_event_open(&attr, -1, 0, -1, 0);
	if (fd <= 0) {
		fprintf(stderr, "ERR: failed to open perf event %s\n",
			strerror(errno));
		goto err;
	}

	/* Assign the program to the tracepoint perf event */
	err = ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_fd);
	if (err) {
		fprintf(stderr, "ERR: failed to connect perf event with eBPF prog %s\n",
			strerror(errno));
		goto err;
	}

	/* ... and finally enable the event. */
	err = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	if (err) {
		fprintf(stderr, "ERR: failed to enable perf event %s\n",
			strerror(errno));
		goto err;
	}

	/*
	 * As far as this program is concerned, we don't care about
	 * the perf event file descriptor, it will get closed when
	 * the program is terminated. But normally you want to call
	 * close(fd) when you stop using it.
	 */
	return obj;

err:
	bpf_object__close(obj);
	return NULL;
}

int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	struct bpf_object *bpf_obj;
	struct config cfg;
	int stats_map_fd;
	int interval = 2;
	int err;

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	bpf_obj = load_bpf_and_trace_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s)\n", cfg.filename);
	}

	stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
	if (stats_map_fd < 0)
		return EXIT_FAIL_BPF;

	map_expect.key_size    = sizeof(__s32);
	map_expect.value_size  = sizeof(__u64);

	err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

	stats_poll(stats_map_fd, info.type, interval);
	return EXIT_OK;
}
