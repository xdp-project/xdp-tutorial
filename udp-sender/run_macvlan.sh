#!/bin/bash -x
ip netns add ns1

ip netns exec ns1 ip link set lo up

ip link add macvlan1 link ens1 type macvlan mode bridge
ip link set macvlan1 netns ns1

ip netns exec ns1 ip link set macvlan1 up
ip netns exec ns1 ip addr add 10.1.0.253/24 dev macvlan1

iptables -P FORWARD ACCEPT
iptables -F FORWARD

export LD_LIBRARY_PATH=/usr/local/lib
ip netns exec ns1 ./af_xdp_user -d macvlan1
#gdb ./af_xdp_user

