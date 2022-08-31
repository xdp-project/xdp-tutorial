#!/bin/bash -x
ip netns exec ns2 iperf3 -s &
pid=$!
ip netns exec ns1 iperf3 -c 10.10.0.20 -t 60
kill $pid
wait
