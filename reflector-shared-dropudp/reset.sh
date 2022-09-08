#!/bin/bash -x

ip link delete br0
ip link delete veth1
ip link delete veth2

ip netns delete ns2
ip netns delete ns1
