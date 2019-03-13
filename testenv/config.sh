#!/bin/bash

# These are the config options for the testlab


SETUP_SCRIPT="$(dirname "$0")/setup-env.sh"
STATEDIR="${TMPDIR:-/tmp}/xdp-tutorial-testlab"
IP6_SUBNET=fc00:dead:cafe # must have exactly three :-separated elements
IP6_PREFIX_SIZE=64 # Size of assigned prefixes
IP6_FULL_PREFIX_SIZE=48 # Size of IP6_SUBNET
IP4_SUBNET=10.11
IP4_PREFIX_SIZE=24 # Size of assigned prefixes
IP4_FULL_PREFIX_SIZE=16 # Size of IP4_SUBNET
VLAN_IDS=(1 2)
GENERATED_NAME_PREFIX="xdptut"
