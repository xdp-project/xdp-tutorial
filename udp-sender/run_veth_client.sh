#!/bin/bash -x
route add -net 10.10.0.10/16 gw 10.1.0.2
./udp-sender 10.10.0.10 8000
route del -net 10.10.0.10/16

