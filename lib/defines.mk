CFLAGS ?= -O2 -g
BPF_CFLAGS ?= -Wno-visibility

include $(LIB_DIR)/../config.mk

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
SBINDIR?=$(PREFIX)/sbin
HDRDIR?=$(PREFIX)/include/xdp
DATADIR?=$(PREFIX)/share
MANDIR?=$(DATADIR)/man
BPF_DIR_MNT ?=/sys/fs/bpf
BPF_OBJECT_DIR ?=$(LIBDIR)/bpf
MAX_DISPATCHER_ACTIONS ?=10

# headers/ dir contains include header files needed to compile BPF programs
HEADER_DIR = $(LIB_DIR)/../headers
# include/ dir contains the projects own include header files
INCLUDE_DIR = $(LIB_DIR)/../include
TEST_DIR = $(LIB_DIR)/testing
LIBBPF_DIR := $(LIB_DIR)/libbpf

DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_DIR)\"

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

HAVE_FEATURES :=

CFLAGS += $(DEFINES) $(ARCH_INCLUDES)
BPF_CFLAGS += $(DEFINES) $(ARCH_INCLUDES)

CONFIGMK := $(LIB_DIR)/../config.mk
LIBMK := Makefile $(CONFIGMK) $(LIB_DIR)/defines.mk $(LIB_DIR)/common.mk $(LIB_DIR)/util/util.mk

