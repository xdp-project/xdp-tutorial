# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern xdp_prog_kern2
XDP_TARGETS  += xdp_prog_kern3
XDP_TARGETS  += xdp_prog_kern4
XDP_TARGETS  += xdp_prog_fail1
XDP_TARGETS  += xdp_prog_fail2
XDP_TARGETS  += xdp_prog_fail3

# USER_TARGETS :=

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

COPY_LOADER := xdp_loader
COPY_STATS  := xdp_stats
EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
