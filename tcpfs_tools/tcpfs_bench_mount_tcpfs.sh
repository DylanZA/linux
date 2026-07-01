#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

TOOLS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

SERVER="${SERVER:-192.168.1.238:9000}"
OPS="${OPS:-tcpfs_s3}"
ARG="${ARG:-publicbucket}"
MNT="${MNT:-/tmp/tcpfs}"
TIMEOUT_MS="${TIMEOUT_MS:-5000}"
BUF_SIZE="${BUF_SIZE:-4096}"
BUF_COUNT="${BUF_COUNT:-8}"
IFNAME="${IFNAME:-}"
MTU="${MTU:-8000}"

configure_network()
{
	[ -n "$IFNAME" ] || return 0
	case "$MTU" in
	''|*[!0-9]*)
		echo "invalid MTU: $MTU" >&2
		exit 2
		;;
	esac
	if [ "$MTU" -lt 68 ] || [ "$MTU" -gt 65535 ]; then
		echo "MTU is outside the IPv4 interface range: $MTU" >&2
		exit 2
	fi

	ip link set dev "$IFNAME" mtu "$MTU"
	actual=$(cat "/sys/class/net/$IFNAME/mtu")
	if [ "$actual" != "$MTU" ]; then
		echo "$IFNAME MTU is $actual, expected $MTU" >&2
		exit 1
	fi

	case "$SERVER" in
	\[*\]:*)
		host=${SERVER#\[}
		host=${host%%\]*}
		payload=$((MTU - 48))
		ping_family=-6
		;;
	*)
		host=${SERVER%:*}
		payload=$((MTU - 28))
		ping_family=
		;;
	esac
	if [ "$MTU" -gt 1500 ]; then
		# shellcheck disable=SC2086
		ping $ping_family -n -c 1 -W 2 -M do -s "$payload" "$host" \
			>/dev/null || {
			echo "$MTU-byte path MTU check to $host failed" >&2
			exit 1
		}
	fi

	ethtool -K "$IFNAME" rx-gro-hw off
	ethtool -G "$IFNAME" tcp-data-split on
	echo "tcpfs benchmark network: interface=$IFNAME mtu=$MTU" >&2
}

mkdir -p "$MNT"
configure_network

if ! pgrep -f "tcpfs_s3_loader" >/dev/null 2>&1; then
	"$TOOLS_DIR/tcpfs_s3_loader" &
	sleep 0.2
fi

modprobe tcpfs
if ! mountpoint -q "$MNT"; then
	mount -t tcpfs none "$MNT" -o \
		"servers=$SERVER,ops=$OPS,arg=$ARG,timeout_ms=$TIMEOUT_MS,buf_size=$BUF_SIZE,buf_count=$BUF_COUNT"
fi

echo "$MNT"
