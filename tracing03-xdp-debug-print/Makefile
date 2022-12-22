# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_prog_kern
USER_TARGETS := trace_read

COPY_LOADER = xdp-loader

LLC ?= llc
CLANG ?= clang
CC := gcc

COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o
