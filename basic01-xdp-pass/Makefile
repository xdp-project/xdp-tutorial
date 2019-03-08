# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_pass_kern
USER_TARGETS := xdp_pass
USER_C := xdp_pass_user.c


LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/
COMMON_OBJS := $(COMMON_DIR)/common_params.o

include $(COMMON_DIR)/common.mk
