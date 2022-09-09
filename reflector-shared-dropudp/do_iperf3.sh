#!/bin/bash -x
ip netns exec ns2 iperf3 -s &
pid=$!
sleep 1
ip netns exec ns1 iperf3 -c 10.10.0.20 -u -t 60 -b 0
kill $pid
wait
