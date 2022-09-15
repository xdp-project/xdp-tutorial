#!/bin/bash -x
route add 10.10.0.10/16 via 192.168.17.10
./udp-sender 10.10.0.10 8000
route delete 10.10.0.10/16 via 192.168.17.10

