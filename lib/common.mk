# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  LIB_DIR = ../lib/
#  include $(LIB_DIR)/common.mk
#
# It is expected that you define the variables:
#  BPF_TARGETS and USER_TARGETS
# as a space-separated list
#
BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}
BPF_SKEL = ${BPF_SKEL_OBJ:.o=.skel.h}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}
BPF_OBJ_INSTALL ?= $(BPF_OBJ)

# Expect this is defined by including Makefile, but define if not
LIB_DIR ?= ../lib
LDLIBS ?= $(USER_LIBS)

# get list of objects in util
include $(LIB_DIR)/util/util.mk

include $(LIB_DIR)/defines.mk

# Extend if including Makefile already added some
LIB_OBJS += $(foreach obj,$(UTIL_OBJS),$(LIB_DIR)/util/$(obj))

EXTRA_DEPS +=
EXTRA_USER_DEPS +=

# Detect submodule libbpf source file changes
ifeq ($(SYSTEM_LIBBPF),n)
	LIBBPF_SOURCES := $(wildcard $(LIBBPF_DIR)/src/*.[ch])
endif

# The BPF tracing header (/usr/include/bpf/bpf_tracing.h) need to know
# CPU architecture due to PT_REGS_PARM resolution of ASM call convention
#
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS += -I$(INCLUDE_DIR) -I$(HEADER_DIR) -I$(LIB_DIR)/util -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS)
BPF_CFLAGS += -I$(INCLUDE_DIR) -I$(HEADER_DIR) -I$(LIB_DIR)/install/include $(EXTRA_CFLAGS)
LDFLAGS += -L$(LIB_DIR)/install/lib

BPF_HEADERS := $(wildcard $(HEADER_DIR)/*/*.h) $(wildcard $(INCLUDE_DIR)/*/*.h)

all: $(USER_TARGETS) $(BPF_OBJ) $(EXTRA_TARGETS) $(BPF_SKEL)

.PHONY: clean
clean::
	$(Q)rm -f $(USER_TARGETS) $(BPF_OBJ) $(USER_OBJ) $(USER_GEN) $(USER_TARGETS_OBJS) *.ll

$(OBJECT_LIBBPF): $(LIBBPF_SOURCES)
	$(Q)$(MAKE) -C $(LIB_DIR) libbpf

$(OBJECT_LIBXDP): $(LIBXDP_SOURCES)
	$(Q)$(MAKE) -C $(LIB_DIR) libxdp

$(CONFIGMK):
	$(Q)$(MAKE) -C $(LIB_DIR)/.. config.mk

# Create expansions for dependencies
LIB_H := ${LIB_OBJS:.o=.h}

# Detect if any of common obj changed and create dependency on .h-files
$(LIB_OBJS): %.o: %.c %.h $(LIB_H)
	$(Q)$(MAKE) -C $(dir $@) $(notdir $@)

# Allows including Makefile to define USER_TARGETS_OBJS to compile and link with
$(USER_TARGETS_OBJS): %.o: %.c %.h  $(USER_TARGETS_OBJS_DEPS)
	$(QUIET_CC)$(CC) $(CFLAGS) -Wall -c -o $@ $<

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) $(EXTRA_USER_DEPS) $(BPF_SKEL) $(USER_TARGETS_OBJS)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(LIB_OBJS) $(USER_TARGETS_OBJS) \
	 $< $(LDLIBS)

$(BPF_OBJ): %.o: %.c $(KERN_USER_H) $(EXTRA_DEPS) $(BPF_HEADERS) $(LIBMK)
	$(QUIET_CLANG)$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(QUIET_LLC)$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(BPF_SKEL): %.skel.h: %.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton ${@:.skel.h=.o} > $@


.PHONY: test
ifeq ($(TEST_FILE),)
test:
	@echo "    No tests defined"
else
test: all
	$(Q)$(TEST_DIR)/test_runner.sh $(TEST_FILE)
endif
