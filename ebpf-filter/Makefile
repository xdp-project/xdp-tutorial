# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


XDP_TARGETS  := af_xdp_kern_filter
USER_TARGETS := af_xdp_user ebpf-xdp_stats

LIBBPF_DIR = ../../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
LIBS += -lxdp -lz -lpthread
