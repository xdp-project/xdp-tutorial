#!/bin/bash

set -o errexit
set -o nounset

source $(dirname $0)/config.sh

NEEDED_TOOLS="ethtool ip tc"
MAX_NAMELEN=15

die()
{
    echo "$1" >&2
    exit 1
}

check_prereq()
{
    for t in $NEEDED_TOOLS; do
        which "$t" > /dev/null || die "Missing required tools: $t"
    done

    [ -d "$STATEDIR" ] || mkdir -p "$STATEDIR" || die "Unable to create state dir $STATEDIR"
}

get_num()
{
    echo 1
}

create()
{
    local NS="$1"
    local STATEFILE="$STATEDIR/$NS.state"

    [ -e "$STATEFILE" ] && die "Environment for $NS seems to already exist"
    [ "${#NS}" -gt "$MAX_NAMELEN" ] && die "Environment name $NS is too long (max $MAX_NAMELEN)"

    local NUM=$(get_num "$NS")
    local PEERNAME="testl-ve-$NUM"
    local PREFIX="${IP_SUBNET}:${NUM}::"

    touch "$STATEFILE"

    ip netns add "$NS"
    ip link add dev "$NS" type veth peer name "$PEERNAME"
    ethtool -K "$NS" rxvlan off txvlan off
    ethtool -K "$PEERNAME" rxvlan off txvlan off
    ip link set dev "$PEERNAME" netns "$NS"
    ip link set dev "$NS" up
    sysctl -w net.ipv6.conf.$NS.accept_dad=0 >/dev/null
    ip addr add dev "$NS" "${PREFIX}2/64"

    ip -n "$NS" link set dev "$PEERNAME" name veth0
    ip -n "$NS" link set dev lo up
    ip -n "$NS" link set dev veth0 up
    ip netns exec "$NS" sysctl -w net.ipv6.conf.veth0.accept_dad=0 >/dev/null
    ip -n "$NS" addr add dev veth0 "${PREFIX}1/64"

    ping -c 1 "${PREFIX}1"

    echo "NUM=$NUM" > "$STATEFILE"

}

teardown()
{
    local NS="$1"
    STATEFILE="$STATEDIR/$NS.state"

    [ -e "$STATEFILE" ] || die "Environment for $NS doesn't seem to exist"

    ip link del dev "$NS"
    ip netns del "$NS"
    rm -f "$STATEFILE"
}

ns_exec()
{
    local NS="$1"
    shift
    STATEFILE="$STATEDIR/$NS.state"

    [ -e "$STATEFILE" ] || die "Environment for $NS doesn't seem to exist"

    ip netns exec "$NS" "$@"
}

enter()
{
    ns_exec "$1" "${SHEEL:-bash}"
}



CMD=$1
shift
NAME=$1
shift

check_prereq
$CMD $NAME "$@"
