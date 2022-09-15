#!/bin/bash -x
route add -host 10.10.0.10 gw 192.168.17.10
./udp-sender 10.10.0.10 8000
route del -host 10.10.0.10

