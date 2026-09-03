#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
vng=${VNG:-$HOME/dev/virtme-ng/vng}
server=${DATAFS_S3_SERVER:-192.168.1.238:9000}
bucket=${DATAFS_S3_BUCKET:-publicbucket}
object=${DATAFS_S3_OBJECT:-out.data}
iface=${DATAFS_S3_IFACE:-eth0}
bridge=${DATAFS_S3_BRIDGE:-br0}
mtu=32000
length=1073741824
mtu_file=/sys/class/net/$bridge/mtu

[[ $mtu =~ ^[0-9]+$ ]] || {
	echo "datafs benchmark: invalid MTU: $mtu" >&2
	exit 2
}
(( mtu >= 68 && mtu <= 65535 )) || {
	echo "datafs benchmark: MTU is outside the IPv4 interface range: $mtu" >&2
	exit 2
}
[[ $length =~ ^[0-9]+$ ]] && (( length > 0 && length <= 0xffffffff )) || {
	echo "datafs benchmark: invalid read length: $length" >&2
	exit 2
}
[[ -r $mtu_file ]] || {
	echo "datafs benchmark: host bridge $bridge does not exist" >&2
	exit 1
}
actual=$(<"$mtu_file")
(( actual >= mtu )) || {
	echo "datafs benchmark: host bridge $bridge MTU is $actual; $mtu is required" >&2
	exit 1
}

cd "$root"
make -j4
make -C datafs_tools

printf -v command '%q ' "$root/datafs_tools/datafs_benchmark_guest.sh" \
	"$server" "$bucket" "$object" "$iface" "$mtu" "$length"
timeout 60 "$vng" --disable-microvm --memory 4G --cpu 4 \
	--no-virtme-ng-init --user root -n "bridge=$bridge" -- \
	bash -c "cd $(printf %q "$root"); $command"
