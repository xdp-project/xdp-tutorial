# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_BTF_TARGETS := xdp_prog_kern
XDP_BTF_OBJ = ${XDP_BTF_TARGETS:=.o}

_all: llvm-check pahole-check $(XDP_BTF_OBJ) xdp_loader

COPY_LOADER := xdp_loader

COMMON_DIR = ../common/
include $(COMMON_DIR)/common.mk

PAHOLE ?= pahole

.PHONY: $(PAHOLE)

TEST_PAHOLE := "$(PAHOLE) --help 2>&1 | grep BTF"

pahole-check: $(PAHOLE)
	for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done
	echo OOO
	if [ ! $(TEST_PAHOLE) > /dev/null 2>&1 ]; then \
		echo "Tool pahole too old, missing BTF support" ;\
		exit 1; \
	else \
		echo "Using pahole to encode BTF info in ELF-object"; \
	fi

$(XDP_BTF_OBJ): %.o: %.c  Makefile $(COMMON_MK)
	echo $(USE_PAHOLE)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	$(PAHOLE) --btf_encode $@
