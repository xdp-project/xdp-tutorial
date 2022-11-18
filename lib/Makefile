
LIBBPF_CFLAGS:=$(if $(CFLAGS),$(CFLAGS),-g -O2 -Werror -Wall) -fPIC

LIB_DIR = .
LIB_INSTALL := $(LIB_DIR)/install
include defines.mk

SUBDIRS=

all: $(OBJECT_LIBBPF) $(OBJECT_LIBXDP)
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo "  $$i"; $(MAKE) -C $$i; done

.PHONY: clean
clean: libbpf_clean libxdp_clean
	@for i in $(SUBDIRS); \
	do $(MAKE) -C $$i clean; done
	$(Q)find $(LIB_INSTALL) -type f -not -name .gitignore -delete
	$(Q)find $(LIB_INSTALL) -type d -empty -delete

install:
	install -m 0755 -d $(DESTDIR)$(HDRDIR)
	$(MAKE) -C libxdp install
	$(MAKE) -C testing install


libbpf: $(OBJECT_LIBBPF)
libxdp: libbpf $(OBJECT_LIBXDP)

# Handle libbpf as git submodule
ifeq ($(SYSTEM_LIBBPF),n)
ifeq ($(VERBOSE),0)
P:= >/dev/null
endif

# Detect submodule libbpf source file changes
LIBBPF_SOURCES := $(wildcard libbpf/src/*.[ch])

$(LIB_INSTALL)/lib/libbpf.a: $(LIBBPF_SOURCES)
	@echo ; echo "  libbpf"
	$(QUIET_CC)$(MAKE) -C libbpf/src CFLAGS="$(LIBBPF_CFLAGS)" $P
	$(QUIET_INSTALL)$(MAKE) -C libbpf/src DESTDIR=../../$(LIB_INSTALL) PREFIX= install_headers $P
	$(Q)cp -fp libbpf/src/libbpf.a install/lib/

.PHONY: libbpf_clean
libbpf_clean:
	$(Q)$(MAKE) -C libbpf/src clean $P

else

libbpf_clean:
	@echo -n
endif

# Handle libbpf as git submodule
ifeq ($(SYSTEM_LIBXDP),n)
ifeq ($(VERBOSE),0)
P:= >/dev/null
endif

# Detect submodule libbpf source file changes
LIBXDP_SOURCES := $(wildcard xdp-tools/lib/libxdp/libxdp*.[ch]) xdp-tools/lib/libxdp/xsk.c


$(LIB_INSTALL)/lib/libxdp.a: $(LIBXDP_SOURCES)
	@echo ; echo "  libxdp"
	$(QUIET_CC)$(MAKE) -C xdp-tools BUILD_STATIC_ONLY=1 libxdp  $P
	$(QUIET_INSTALL)$(MAKE) -C xdp-tools DESTDIR=../../../$(LIB_INSTALL) PREFIX= BUILD_STATIC_ONLY=1 libxdp_install $P

.PHONY: libxdp_clean
libxdp_clean:
	$(Q)$(MAKE) -C xdp-tools clean $P

else

libxdp_clean:
	@echo -n
endif
