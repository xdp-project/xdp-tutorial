# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_prog_kern_02 xdp_prog_kern_03
XDP_TARGETS  += xdp_vlan01_kern
XDP_TARGETS  += xdp_vlan02_kern
USER_TARGETS := xdp_prog_user

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

COPY_LOADER := xdp_loader
COPY_STATS  := xdp_stats
EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
