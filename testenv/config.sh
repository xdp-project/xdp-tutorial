#!/bin/bash

# These are the config options for the testlab


SETUP_SCRIPT="$(dirname "$0")/setup-env.sh"
STATEDIR="${TMPDIR:-/tmp}/xdp-tutorial-testlab"
IP6_SUBNET=fc00:dead:cafe # must have exactly three :-separated elements
IP6_PREFIX_SIZE=64
IP4_SUBNET=10.11
IP4_PREFIX_SIZE=24
VLAN_IDS=(1 2)
GENERATED_NAME_PREFIX="xdptut"
