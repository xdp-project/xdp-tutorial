#!/bin/bash -x
export LD_LIBRARY_PATH=/usr/local/lib
./af_xdp_user -S -d eth0
