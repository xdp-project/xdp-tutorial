#!/bin/bash

# These are the config options for the testlab


SETUP_SCRIPT="$(dirname "$0")/setup-env.sh"
STATEDIR="${TMPDIR:-/tmp}/xdp-tutorial-testlab"
IP_SUBNET=fc00:dead:cafe
IP_PREFIX_SIZE=64
GENERATED_NAME_PREFIX="xdptut"
