#!/bin/bash -x
cd ../reflector-shared-dropudp/
export LD_LIBRARY_PATH=/usr/local/lib
./af_xdp_user -d ens9f0 -r ens9f0
