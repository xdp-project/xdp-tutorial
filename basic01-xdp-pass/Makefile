# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TARGETS := xdp_pass

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src/

XDP_C = ${TARGETS:=_kern.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C = ${TARGETS:=_user.c}
USER_OBJ = ${USER_C:.c=.o}
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

COMMON_OBJS := ../common/common_params.o
# Supports adding more COMMON_OBJS
# COMMON_OBJS += ../common/common_bpf.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

CFLAGS ?= -I$(LIBBPF_DIR)/root/usr/include/
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

LIBS = -lbpf -lelf

all: llvm-check $(TARGETS) $(XDP_OBJ)

.PHONY: clean $(CLANG) $(LLC)

clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean;
	make -C ../common/ clean
	rm -f $(TARGETS)
	rm -f $(XDP_OBJ)
	rm -f $(USER_OBJ)
	rm -f *.ll
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p root; DESTDIR=root $(MAKE) install_headers; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C ../common/

$(TARGETS): %: %_user.c $(OBJECT_LIBBPF) Makefile $(COMMON_OBJS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)

$(XDP_OBJ): %.o: %.c
	$(CLANG) -S \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
