# SPDX-License-Identifier: (GPL-2.0)
LIB_DIR = ../lib
include $(LIB_DIR)/defines.mk

all: common_params.o

CFLAGS += -I$(LIB_DIR)/install/include

common_params.o: common_params.c common_params.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	$(Q)rm -f *.o
