#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
vng=${VNG:-$HOME/dev/virtme-ng/vng}
mode=${1:-nfs}
s3_server=${TCPFS_S3_SERVER:-192.168.1.238:9000}
s3_bucket=${TCPFS_S3_BUCKET:-publicbucket}
s3_object=${TCPFS_S3_OBJECT:-out.data}
s3_iface=${TCPFS_S3_IFACE:-eth0}
s3_bridge=${TCPFS_S3_BRIDGE:-br0}
s3_mtu=${TCPFS_MTU:-8000}

check_bridge_mtu()
{
	local mtu_file=/sys/class/net/$s3_bridge/mtu
	local actual

	[[ $s3_mtu =~ ^[0-9]+$ ]] || {
		echo "tcpfs smoke: invalid MTU: $s3_mtu" >&2
		exit 2
	}
	if (( s3_mtu < 68 || s3_mtu > 65535 )); then
		echo "tcpfs smoke: MTU is outside the IPv4 interface range: $s3_mtu" >&2
		exit 2
	fi
	[[ -r $mtu_file ]] || {
		echo "tcpfs smoke: host bridge $s3_bridge does not exist" >&2
		exit 1
	}
	actual=$(<"$mtu_file")
	if (( actual < s3_mtu )); then
		echo "tcpfs smoke: host bridge $s3_bridge MTU is $actual; $s3_mtu is required" >&2
		exit 1
	fi
}

run_guest()
{
	local network=$1
	local pci=$2
	shift 2
	local command

	printf -v command '%q ' "$root/tcpfs_tools/tcpfs_smoke_guest.sh" "$@"
	if [[ $pci == yes ]]; then
		timeout 60 "$vng" --disable-microvm --memory 3G --cpu 4 \
			--no-virtme-ng-init --user root -n "$network" -- \
			bash -c "cd $(printf %q "$root"); $command"
	else
		timeout 60 "$vng" --cpu 4 --no-virtme-ng-init --user root \
			-n "$network" -- bash -c \
			"cd $(printf %q "$root"); $command"
	fi
}

case $mode in
s3-nodev|s3-nic)
	check_bridge_mtu
	;;
esac

cd "$root"
make -j4
make -C tcpfs_tools

case $mode in
nfs)
	run_guest user no nfs
	;;
s3-nodev)
	run_guest "bridge=$s3_bridge" no s3 "$s3_server" "$s3_bucket" "$s3_object" \
		"" "$s3_iface" "$s3_mtu"
	;;
s3-nic)
	run_guest "bridge=$s3_bridge" yes s3 "$s3_server" "$s3_bucket" "$s3_object" \
		"$s3_iface" "$s3_iface" "$s3_mtu"
	;;
all)
	"$0" nfs
	"$0" s3-nodev
	"$0" s3-nic
	;;
*)
	echo "usage: $0 {nfs|s3-nodev|s3-nic|all}" >&2
	exit 2
	;;
esac
