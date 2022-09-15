#!/bin/bash -x
route add -host 10.10.0.10 gw 10.1.0.2
./udp-sender 10.10.0.10 8000
route del -host 10.10.0.10

