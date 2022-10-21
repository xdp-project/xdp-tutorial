#!/bin/bash -x
bpftool prog loadall af_xdp_kern.o /sys/fs/bpf/afxdp pinmaps /sys/fs/bpf/afxdp_maps
export LD_LIBRARY_PATH=/usr/local/lib
ip tuntap add mode tun tun0
ip link set dev tun0 addr 10.1.1.2/24
ip link set dev tun0 up
./af_xdp_user_noload -S -d enp25s0 -Q 0 --filename ./af_xdp_kern.o
