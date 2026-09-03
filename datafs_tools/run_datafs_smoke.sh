#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
vng=${VNG:-$HOME/dev/virtme-ng/vng}
mode=${1:-datafs-nfs}
s3_server=${DATAFS_S3_SERVER:-192.168.1.238:9000}
s3_bucket=${DATAFS_S3_BUCKET:-publicbucket}
s3_object=${DATAFS_S3_OBJECT:-out.data}
s3_iface=${DATAFS_S3_IFACE:-eth0}
s3_bridge=${DATAFS_S3_BRIDGE:-br0}
s3_mtu=32000

check_bridge_mtu()
{
	local mtu_file=/sys/class/net/$s3_bridge/mtu
	local actual

	[[ $s3_mtu =~ ^[0-9]+$ ]] || {
		echo "datafs smoke: invalid MTU: $s3_mtu" >&2
		exit 2
	}
	if (( s3_mtu < 68 || s3_mtu > 65535 )); then
		echo "datafs smoke: MTU is outside the IPv4 interface range: $s3_mtu" >&2
		exit 2
	fi
	[[ -r $mtu_file ]] || {
		echo "datafs smoke: host bridge $s3_bridge does not exist" >&2
		exit 1
	}
	actual=$(<"$mtu_file")
	if (( actual < s3_mtu )); then
		echo "datafs smoke: host bridge $s3_bridge MTU is $actual; $s3_mtu is required" >&2
		exit 1
	fi
}

run_guest()
{
	local network=$1
	local pci=$2
	shift 2
	local command

	printf -v command '%q ' "$root/datafs_tools/datafs_smoke_guest.sh" "$@"
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
datafs-s3|datafs-s3-devmem)
	check_bridge_mtu
	;;
esac

cd "$root"
make -j4
make -C datafs_tools

case $mode in
datafs-nfs)
	run_guest user no datafs-nfs
	;;
datafs-rest)
	run_guest user no datafs-rest
	;;
datafs-smb)
	run_guest user no datafs-smb
	;;
datafs-s3)
	run_guest "bridge=$s3_bridge" no datafs-s3 "$s3_server" "$s3_bucket" "$s3_object" \
		"" "$s3_iface" "$s3_mtu"
	;;
datafs-s3-devmem)
	run_guest "bridge=$s3_bridge" yes datafs-s3-devmem "$s3_server" \
		"$s3_bucket" "$s3_object" "$s3_iface" "$s3_iface" "$s3_mtu"
	;;
all)
	"$0" datafs-nfs
	"$0" datafs-rest
	"$0" datafs-smb
	"$0" datafs-s3
	"$0" datafs-s3-devmem
	;;
*)
	echo "usage: $0 {datafs-nfs|datafs-rest|datafs-smb|datafs-s3|datafs-s3-devmem|all}" >&2
	exit 2
	;;
esac
