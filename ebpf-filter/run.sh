#!/bin/bash -x
export LD_LIBRARY_PATH=/usr/local/lib
ip tuntap add mode tap tap0
ip link set dev tap0 up
./af_xdp_user -S -d enp25s0 -Q 0 --filename ./af_xdp_kern_pass.o
