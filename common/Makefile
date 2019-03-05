# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_params.o

CFLAGS := -g -Wall

common_params.o: common_params.c common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o

