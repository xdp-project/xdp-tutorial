#!/usr/bin/env bash

#
# Clone and build the tutorial
#
git clone --recurse-submodules https://github.com/xdp-project/xdp-tutorial.git
# This was successfully tested with commit 94471eed572a733a71b096975b3cb72509113e6f
cd xdp-tutorial
make
