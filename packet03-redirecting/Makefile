# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern
USER_TARGETS := xdp_prog_user

COMMON_DIR = ../common

COPY_LOADER := xdp-loader
COPY_STATS  := xdp_stats
EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h
COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

include $(COMMON_DIR)/common.mk
