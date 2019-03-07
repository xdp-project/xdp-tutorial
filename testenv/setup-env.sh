#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script to setup things inside a test environment, used by testenv.sh for
# executing commands.
#
# Author:   Toke Høiland-Jørgensen (toke@redhat.com)
# Date:     7 March 2019
# Copyright (c) 2019 Red Hat


die()
{
    echo "$1" >&2
    exit 1
}

[ -n "$TESTENV_NAME" ] || die "TESTENV_NAME missing from environment"
[ -n "$1" ] || die "Usage: $0 <command to execute>"

set -o nounset

mount -t bpf bpf /sys/fs/bpf/ || die "Unable to mount /sys/fs/bpf inside test environment"

exec "$@"
