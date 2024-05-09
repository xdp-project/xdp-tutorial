#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script to setup and manage test environment for the XDP tutorial.
# See README.org for instructions on how to use.
#
# Author:   Toke Høiland-Jørgensen (toke@redhat.com)
# Date:     6 March 2019
# Copyright (c) 2019 Red Hat

set -o errexit
set -o nounset
umask 077

source "$(dirname "$0")/config.sh"

NEEDED_TOOLS="ethtool ip tc ping"
MAX_NAMELEN=15

# Global state variables that will be set by options etc below
GENERATE_NEW=0
CLEANUP_FUNC=
STATEFILE=
CMD=
NS=
XDP_LOADER=./xdp-loader
XDP_STATS=./xdp_stats
LEGACY_IP=0
USE_VLAN=0
RUN_ON_INNER=0

# State variables that are written to and read from statefile
STATEVARS=(IP6_PREFIX IP4_PREFIX
           INSIDE_IP6 INSIDE_IP4 INSIDE_MAC
           OUTSIDE_IP6 OUTSIDE_IP4 OUTSIDE_MAC
           ENABLE_IPV4 ENABLE_VLAN)
IP6_PREFIX=
IP4_PREFIX=
INSIDE_IP6=
INSIDE_IP4=
INSIDE_MAC=
OUTSIDE_IP6=
OUTSIDE_IP4=
OUTSIDE_MAC=
ENABLE_IPV4=0
ENABLE_VLAN=0

die()
{
    echo "$1" >&2
    exit 1
}

check_prereq()
{
    local max_locked_mem=$(ulimit -l)

    for t in $NEEDED_TOOLS; do
        which "$t" > /dev/null || die "Missing required tools: $t"
    done

    if [ "$EUID" -ne "0" ]; then
        die "This script needs root permissions to run."
    fi

    [ -d "$STATEDIR" ] || mkdir -p "$STATEDIR" || die "Unable to create state dir $STATEDIR"

    if [ "$max_locked_mem" != "unlimited" ]; then
	ulimit -l unlimited || die "Unable to set ulimit"
    fi
}

get_nsname()
{
    local GENERATE=${1:-0}

    if [ -z "$NS" ]; then
        [ -f "$STATEDIR/current" ] && NS=$(< "$STATEDIR/current")

        if [ "$GENERATE" -eq "1" ] && [ -z "$NS" -o "$GENERATE_NEW" -eq "1" ]; then
            NS=$(printf "%s-%04x" "$GENERATED_NAME_PREFIX" $RANDOM)
        fi
    fi

    if [ "${#NS}" -gt "$MAX_NAMELEN" ]; then
        die "Environment name '$NS' is too long (max $MAX_NAMELEN)"
    fi

    STATEFILE="$STATEDIR/${NS}.state"
}

ensure_nsname()
{
    [ -z "$NS" ] && die "No environment selected; use --name to select one or 'setup' to create one"
    [ -e "$STATEFILE" ] || die "Environment for $NS doesn't seem to exist"

    echo "$NS" > "$STATEDIR/current"

    read_statefile
}

get_num()
{
    local num=1
    if [ -f "$STATEDIR/highest_num" ]; then
        num=$(( 1 + $(< "$STATEDIR/highest_num" )))
    fi

    echo $num > "$STATEDIR/highest_num"
    printf "%x" $num
}

write_statefile()
{
    [ -z "$STATEFILE" ] && return 1
    echo > "$STATEFILE"
    for var in "${STATEVARS[@]}"; do
        echo "${var}='$(eval echo '$'$var)'" >> "$STATEFILE"
    done
}

read_statefile()
{
    local value
    for var in "${STATEVARS[@]}"; do
        value=$(source "$STATEFILE"; eval echo '$'$var)
        eval "$var=\"$value\""
    done
}

cleanup_setup()
{
    echo "Error during setup, removing partially-configured environment '$NS'" >&2
    set +o errexit
    ip netns del "$NS" 2>/dev/null
    ip link del dev "$NS" 2>/dev/null
    rm -f "$STATEFILE"
}

cleanup_teardown()
{
    echo "Warning: Errors during teardown, partial environment may be left" >&2
}


cleanup()
{
    [ -n "$CLEANUP_FUNC" ] && $CLEANUP_FUNC

    [ -d "$STATEDIR" ] || return 0

    local statefiles=("$STATEDIR"/*.state)

    if [ "${#statefiles[*]}" -eq 1 ] && [ ! -e "${statefiles[0]}" ]; then
        rm -f "${STATEDIR}/highest_num" "${STATEDIR}/current"
        rmdir "$STATEDIR"
    fi
}

iface_macaddr()
{
    local iface="$1"
    local ns="${2:-}"
    local output

    if [ -n "$ns" ]; then
        output=$(ip -br -n "$ns" link show dev "$iface")
    else
        output=$(ip -br link show dev "$iface")
    fi
    echo "$output" | awk '{print $3}'
}

set_sysctls()
{
    local iface="$1"
    local in_ns="${2:-}"
    local nscmd=

    [ -n "$in_ns" ] && nscmd="ip netns exec $in_ns"
    local sysctls=(accept_dad
                   accept_ra
                   mldv1_unsolicited_report_interval
                   mldv2_unsolicited_report_interval)

    for s in ${sysctls[*]}; do
        $nscmd sysctl -w net.ipv6.conf.$iface.${s}=0 >/dev/null
    done
}

wait_for_dev()
{
    local iface="$1"
    local in_ns="${2:-}"
    local retries=5 # max retries
    local nscmd=

    [ -n "$in_ns" ] && nscmd="ip netns exec $in_ns"
    while [ "$retries" -gt "0" ]; do
        if ! $nscmd ip addr show dev $iface | grep -q tentative; then return 0; fi
        sleep 0.5
        retries=$((retries -1))
    done
}

get_vlan_prefix()
{
    # Split the IPv6 prefix, and add the VLAN ID to the upper byte of the fourth
    # element in the prefix. This will break if the global prefix config doesn't
    # have exactly three elements in it.
    local prefix="$1"
    local vid="$2"
    (IFS=:; set -- $prefix; printf "%s:%s:%s:%x::" "$1" "$2" "$3" $(($4 + $vid * 4096)))
}

setup()
{
    get_nsname 1

    echo "Setting up new environment '$NS'"

    [ -e "$STATEFILE" ] && die "Environment for '$NS' already exists"

    local NUM=$(get_num "$NS")
    local PEERNAME="testl-ve-$NUM"
    [ -z "$IP6_PREFIX" ] && IP6_PREFIX="${IP6_SUBNET}:${NUM}::"
    [ -z "$IP4_PREFIX" ] && IP4_PREFIX="${IP4_SUBNET}.$((0x$NUM))."

    INSIDE_IP6="${IP6_PREFIX}2"
    INSIDE_IP4="${IP4_PREFIX}2"
    OUTSIDE_IP6="${IP6_PREFIX}1"
    OUTSIDE_IP4="${IP4_PREFIX}1"

    CLEANUP_FUNC=cleanup_setup

    if ! mount | grep -q /sys/fs/bpf; then
        mount -t bpf bpf /sys/fs/bpf/
    fi

    ip netns add "$NS"
    ip link add dev "$NS" type veth peer name veth0 netns "$NS"

    set_sysctls $NS
    ip link set dev "$NS" up
    ip addr add dev "$NS" "${OUTSIDE_IP6}/${IP6_PREFIX_SIZE}"
    ethtool -K "$NS" rxvlan off txvlan off
    # Prevent neighbour queries on the link
    INSIDE_MAC=$(iface_macaddr veth0 "$NS")
    ip neigh add "$INSIDE_IP6" lladdr "$INSIDE_MAC" dev "$NS" nud permanent

    set_sysctls veth0 "$NS"
    ip -n "$NS" link set dev lo up
    ip -n "$NS" link set dev veth0 up
    ip -n "$NS" addr add dev veth0 "${INSIDE_IP6}/${IP6_PREFIX_SIZE}"
    ip netns exec "$NS" ethtool -K veth0 rxvlan off txvlan off
    # Prevent neighbour queries on the link
    OUTSIDE_MAC=$(iface_macaddr "$NS")
    ip -n "$NS" neigh add "$OUTSIDE_IP6" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent
    # Add route for whole test subnet, to make it easier to communicate between
    # namespaces
    ip -n "$NS" route add "${IP6_SUBNET}::/$IP6_FULL_PREFIX_SIZE" via "$OUTSIDE_IP6" dev veth0

    if [ "$LEGACY_IP" -eq "1" ]; then
        ip addr add dev "$NS" "${OUTSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip -n "$NS" addr add dev veth0 "${INSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip neigh add "$INSIDE_IP4" lladdr "$INSIDE_MAC" dev "$NS" nud permanent
        ip -n "$NS" neigh add "$OUTSIDE_IP4" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent
        ip -n "$NS" route add "${IP4_SUBNET}/${IP4_FULL_PREFIX_SIZE}" via "$OUTSIDE_IP4" dev veth0
        ENABLE_IPV4=1
    else
        ENABLE_IPV4=0
    fi

    if [ "$USE_VLAN" -eq "1" ]; then
        ENABLE_VLAN=1
        for vid in "${VLAN_IDS[@]}"; do
            local vlpx="$(get_vlan_prefix "$IP6_PREFIX" "$vid")"
            local inside_ip="${vlpx}2"
            local outside_ip="${vlpx}1"
            ip link add dev "${NS}.$vid" link "$NS" type vlan id "$vid"
            ip link set dev "${NS}.$vid" up
            ip addr add dev "${NS}.$vid" "${outside_ip}/${IP6_PREFIX_SIZE}"
            ip neigh add "$inside_ip" lladdr "$INSIDE_MAC" dev "${NS}.$vid" nud permanent
            set_sysctls "${NS}/$vid"

            ip -n "$NS" link add dev "veth0.$vid" link "veth0" type vlan id "$vid"
            ip -n "$NS" link set dev "veth0.$vid" up
            ip -n "$NS" addr add dev "veth0.$vid" "${inside_ip}/${IP6_PREFIX_SIZE}"
            ip -n "$NS" neigh add "$outside_ip" lladdr "$OUTSIDE_MAC" dev "veth0.$vid" nud permanent
            set_sysctls "veth0/$vid" "$NS"
        done
    else
        ENABLE_VLAN=0
    fi

    write_statefile

    CLEANUP_FUNC=

    echo -n "Setup environment '$NS' with peer ip ${INSIDE_IP6}"
    [ "$ENABLE_IPV4" -eq "1" ] && echo " and ${INSIDE_IP4}." || echo "."
    echo "Waiting for interface configuration to settle..."
    echo ""
    wait_for_dev "$NS" && wait_for_dev veth0 "$NS"

    LEGACY_IP=0 USE_VLAN=0 run_ping -c 1

    echo "$NS" > "$STATEDIR/current"
}

teardown()
{
    get_nsname && ensure_nsname "$NS"

    echo "Tearing down environment '$NS'"

    CLEANUP_FUNC=cleanup_teardown

    ip link del dev "$NS"
    ip netns del "$NS"
    rm -f "$STATEFILE"
    [ -d "/sys/fs/bpf/$NS" ] && rmdir "/sys/fs/bpf/$NS" || true

    if [ -f "$STATEDIR/current" ]; then
        local CUR=$(< "$STATEDIR/current" )
        [[ "$CUR" == "$NS" ]] && rm -f "$STATEDIR/current"
    fi

    CLEANUP_FUNC=
}

reset()
{
    teardown && setup
}

ns_exec()
{
    get_nsname && ensure_nsname "$NS"

    ip netns exec "$NS" env TESTENV_NAME="$NS" "$SETUP_SCRIPT" "$@"
}

enter()
{
    ns_exec "${SHELL:-bash}"
}

run_ping()
{
    local PING
    local IP

    get_nsname && ensure_nsname "$NS"

    echo "Running ping from inside test environment:"
    echo ""

    if [ "$LEGACY_IP" -eq "1" ]; then
        PING=$(which ping)
        IP="${OUTSIDE_IP4}"
        [ "$USE_VLAN" -eq "0" ] || die "Can't use --legacy-ip and --vlan at the same time."
        [ "$ENABLE_IPV4" -eq "1" ] || die "No legacy IP addresses configured in environment."
    else
        PING=$(which ping6 2>/dev/null || which ping)
        if [ "$USE_VLAN" -eq "0" ]; then
            IP="${OUTSIDE_IP6}"
        else
            [ "$ENABLE_VLAN" -eq "1" ] || die "No VLANs configured in environment."
            IP="$(get_vlan_prefix "$IP6_PREFIX" "${VLAN_IDS[0]}")1"
        fi
    fi

    ns_exec "$PING" "$IP" "$@"
}

run_tcpdump()
{
    get_nsname && ensure_nsname "$NS"

    if [ "$RUN_ON_INNER" -eq "1" ]; then
        ns_exec tcpdump -nei veth0 "$@"
    else
        tcpdump -nei "$NS" "$@"
    fi
}

status()
{
    get_nsname

    echo "Currently selected environment: ${NS:-None}"
    if [ -n "$NS" ] && [ -e "$STATEFILE" ]; then
        read_statefile
        echo -n "  Namespace:      "; ip netns | grep "^$NS"
        echo    "  Prefix:         ${IP6_PREFIX}/${IP6_PREFIX_SIZE}"
        [ "$ENABLE_IPV4" -eq "1" ] && echo    "  Legacy prefix:  ${IP4_PREFIX}0/${IP4_PREFIX_SIZE}"
        echo -n "  Iface:          "; ip -br a show dev "$NS" | sed 's/\s\+/ /g'
    fi
    echo ""

    echo "All existing environments:"
    for f in "$STATEDIR"/*.state; do
        if [ ! -e "$f" ]; then
            echo "  No environments exist"
            break
        fi
        NAME=$(basename "$f" .state)
        echo "  $NAME"
    done
}

print_alias()
{
    local scriptname="$(readlink -e "$0")"
    local sudo=

    [ -t 1 ] && echo "Eval this with \`eval \$($0 alias)\` to create shell alias" >&2

    if [ "$EUID" -ne "0" ]; then
        sudo="sudo "
        echo "WARNING: Creating sudo alias; be careful, this script WILL execute arbitrary programs" >&2
    fi

    echo "" >&2


    echo "alias t='$sudo$scriptname'"
}

#
# This command can be used to populate maps for the assignment 3 of the
# packet03-redirecting lesson. It takes two arguments: the source and the
# destination environment names.
#
populate_redirect_map()
{
    local src="$1"
    local dest="$2"
    local src_mac=$(ip netns exec $src cat /sys/class/net/veth0/address)
    local dest_mac=$(ip netns exec $dest cat /sys/class/net/veth0/address)

    # set bidirectional forwarding
    ./xdp_prog_user -d $src -r $dest --src-mac $src_mac --dest-mac $dest_mac
    ./xdp_prog_user -d $dest -r $src --src-mac $dest_mac --dest-mac $src_mac
}

xdp_load()
{
    get_nsname && ensure_nsname

    [ -x "$XDP_LOADER" ] || die "Loader '$XDP_LOADER' is not executable"
    local objfile=${!#}
    local load_opts="${@:1:$#-1} --pin-path /sys/fs/bpf/$NS"
    $XDP_LOADER load $load_opts $NS $objfile
}

xdp_unload()
{
    get_nsname && ensure_nsname

    [ -x "$XDP_LOADER" ] || die "Loader '$XDP_LOADER' is not executable"
    $XDP_LOADER unload "$@" "$NS"
}

xdp_stats()
{
    get_nsname && ensure_nsname

    [ -x "$XDP_STATS" ] || die "Stats tool '$XDP_STATS' is not executable"
    $XDP_STATS --dev "$NS" "$@"
}

usage()
{
    local FULL=${1:-}

    echo "Usage: $0 [options] <command> [param]"
    echo ""
    echo "Commands:"
    echo "setup                   Setup and initialise new environment"
    echo "teardown                Tear down existing environment"
    echo "reset                   Reset environment to original state"
    echo "exec <command>          Exec <command> inside test environment"
    echo "enter                   Execute shell inside test environment"
    echo "ping                    Run ping inside test environment"
    echo "alias                   Print shell alias for easy access to this script"
    echo "status (or st)          Show status of test environment"
    echo "load                    Load XDP program on outer interface"
    echo "unload                  Unload XDP program on outer interface"
    echo "tcpdump                 Run on outer interface (or inner with --inner)"
    echo "stats                   Run the XDP statistics program"
    echo "redirect <env1> <env2>  Setup redirects for packet03 lessons"
    echo ""

    if [ -z "$FULL" ] ; then
        echo "Use --help to see the list of options."
        exit 1
    fi

    echo "Options:"
    echo "-h, --help          Show this usage text"
    echo ""
    echo "-n, --name <name>   Set name of test environment. If not set, the last used"
    echo "                    name will be used, or a new one generated."
    echo ""
    echo "-g, --gen-new       Generate a new test environment name even though an existing"
    echo "                    environment is selected as the current one."
    echo ""
    echo "-l, --loader <prog> Specify program to use for loading XDP programs."
    echo "                    Device name will be passed to it, along with any additional"
    echo "                    command line options passed after --."
    echo "                    Default: '$XDP_LOADER'"
    echo ""
    echo "-s, --stats <prog>  Specify program to use for getting statistics ('stats' command)."
    echo "                    Device name will be passed to it, along with any additional"
    echo "                    command line options passed after --."
    echo "                    Default: '$XDP_STATS'"
    echo ""
    echo "    --legacy-ip     Enable legacy IP (IPv4) support."
    echo "                    For setup and reset commands this enables configuration of legacy"
    echo "                    IP addresses on the interface, for the ping command it switches to"
    echo "                    legacy ping."
    echo ""
    echo "    --vlan          Enable VLAN support."
    echo "                    When used with the setup and reset commands, these VLAN IDs will"
    echo "                    be configured: ${VLAN_IDS[*]}. The VLAN interfaces are named as"
    echo "                    <ifname>.<vlid>."
    echo "                    When used with the ping command, the pings will be sent on the"
    echo "                    first VLAN ID (${VLAN_IDS[0]})."
    echo ""
    echo "    --inner         Use with tcpdump command to run on inner interface."
    echo ""
    exit 1
}


OPTS="hn:gl:s:"
LONGOPTS="help,name:,gen-new,loader:,stats:,legacy-ip,vlan,inner"

OPTIONS=$(getopt -o "$OPTS" --long "$LONGOPTS" -- "$@")
[ "$?" -ne "0" ] && usage >&2 || true

eval set -- "$OPTIONS"


while true; do
    arg="$1"
    shift

    case "$arg" in
        -h | --help)
            usage full >&2
            ;;
        -n | --name)
            NS="$1"
            shift
            ;;
        -l | --loader)
            XDP_LOADER="$1"
            shift
            ;;
        -s | --stats)
            XDP_STATS="$1"
            shift
            ;;
        -g | --gen-new)
            GENERATE_NEW=1
            ;;
        --legacy-ip)
            LEGACY_IP=1
            ;;
        --vlan)
            USE_VLAN=1
            ;;
        --inner)
            RUN_ON_INNER=1
            ;;
        -- )
            break
            ;;
    esac
done

[ "$#" -eq 0 ] && usage >&2

case "$1" in
    st|sta|status)
        CMD=status
        ;;
    setup|teardown|reset|enter)
        CMD="$1"
        ;;
    load|unload|stats)
        CMD="xdp_$1"
        ;;
    "exec")
        CMD=ns_exec
        ;;
    ping|tcpdump)
        CMD="run_$1"
        ;;
    redirect)
        CMD=populate_redirect_map
        ;;
    "alias")
        print_alias
        exit 0
        ;;
    "help")
        usage full >&2
        ;;
    *)
        usage >&2
        ;;
esac

shift
trap cleanup EXIT
check_prereq
$CMD "$@"
