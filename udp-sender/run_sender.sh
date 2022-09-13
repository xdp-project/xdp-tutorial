#!/bin/bash -x
./udp-sender 10.1.0.2 8000 &
./udp-sender 10.1.0.2 8000
wait
