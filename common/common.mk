
LLC ?= llc
CLANG ?= clang
CC ?= gcc

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C ?= ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

COPY_LOADER ?=
LOADER_DIR := $(COMMON_DIR)/../basic04-pinning-maps

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

COMMON_OBJS ?= $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

CFLAGS ?= -I$(LIBBPF_DIR)/root/usr/include/
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

LIBS = -lbpf -lelf

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(COPY_LOADER)

.PHONY: clean $(CLANG) $(LLC)

clean:
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER)
	rm -f *.ll
	rm -f *~

ifdef COPY_LOADER
$(COPY_LOADER): $(LOADER_DIR)/${COPY_LOADER:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_LOADER)
	cp $(LOADER_DIR)/$(COPY_LOADER) $(COPY_LOADER)
endif

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
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: $(USER_C) $(OBJECT_LIBBPF) Makefile $(COMMON_OBJS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_H)
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
