#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -eEuo pipefail

server=${1:?missing S3 server}
bucket=${2:?missing S3 bucket}
object=${3:?missing S3 object}
iface=${4:?missing receive interface}
mtu=${5:?missing MTU}
length=${6:?missing read length}
mountpoint=/tmp/datafs-bench-mnt
workdir=/tmp/datafs-bench
loader_pid=

fail()
{
	echo "datafs benchmark: FAIL: $*" >&2
	exit 1
}

cleanup()
{
	local rc=$?

	set +e
	if [[ -n $loader_pid ]]; then
		kill "$loader_pid" 2>/dev/null
		wait "$loader_pid" 2>/dev/null
	fi
	mountpoint -q "$mountpoint" && umount "$mountpoint"
	rmmod datafs 2>/dev/null
	if (( rc )); then
		cat "$workdir/loader.log" >&2
		cat "$workdir/benchmark.log" >&2
		dmesg >&2
	fi
	return "$rc"
}
trap cleanup EXIT

wait_for_mount()
{
	local count

	for ((count = 0; count < 100; count++)); do
		mountpoint -q "$mountpoint" && return 0
		kill -0 "$loader_pid" 2>/dev/null || return 1
		sleep 0.05
	done
	return 1
}

configure_network()
{
	local actual host overhead payload

	[[ $mtu =~ ^[0-9]+$ ]] || fail "invalid MTU: $mtu"
	(( mtu >= 68 && mtu <= 65535 )) || fail "MTU is outside the IPv4 range"
	ip link set dev "$iface" mtu "$mtu" || fail "cannot set $iface MTU"
	actual=$(<"/sys/class/net/$iface/mtu")
	[[ $actual == "$mtu" ]] || fail "$iface MTU is $actual, expected $mtu"

	if [[ $server == \[*\]:* ]]; then
		host=${server#\[}
		host=${host%%\]*}
		overhead=48
	else
		host=${server%:*}
		overhead=28
	fi
	payload=$((mtu - overhead))
	ping -n -c 1 -W 2 -M do -s "$payload" "$host" >/dev/null ||
		fail "$mtu-byte path MTU check to $host failed"
	ethtool -L "$iface" combined 1
	ethtool -K "$iface" gro on || fail "cannot enable software GRO"
	ethtool -k "$iface" | grep -q '^generic-receive-offload: on' ||
		fail "software GRO is not enabled on $iface"
	ethtool -K "$iface" rx-gro-hw off
	ethtool -G "$iface" tcp-data-split on
}

run_pread()
{
	local label=$1
	shift

	timeout 30 ./datafs_tools/datafs_bench_read \
		-p "$mountpoint/$object" -m pread -l "$length" -i 1 -w 0 \
		-L "$label" "$@" 2>&1 | tee -a "$workdir/benchmark.log"
}

rm -rf "$workdir"
mkdir -p "$workdir" "$mountpoint"
: >"$workdir/benchmark.log"
dmesg -C
configure_network
modprobe datafs
modprobe udmabuf 2>/dev/null || true

./datafs_tools/datafs_s3_loader --mount "$mountpoint" \
	--server "$server" --arg "$bucket" --loan-sockets 1 \
	--timeout-ms 30000 >"$workdir/loader.log" 2>&1 &
loader_pid=$!
wait_for_mount || fail "datafs mount did not become ready"

remote_size=$(stat -c %s "$mountpoint/$object")
[[ $remote_size =~ ^[0-9]+$ ]] || fail "datafs returned an invalid size"
(( remote_size >= length )) || fail "object is shorter than $length bytes"

echo "datafs benchmark: interface=$iface mtu=$mtu length=$length" |
	tee -a "$workdir/benchmark.log"
echo "datafs benchmark: starting devmem" | tee -a "$workdir/benchmark.log"
/usr/bin/time -f 'datafs-devmem elapsed_s=%e' \
	timeout 40 ./datafs_tools/datafs_devmem_smoke \
		--path "$mountpoint/$object" --length "$length" \
		--iface "$iface" --rxq 0 --require-devmem \
		2>&1 | tee -a "$workdir/benchmark.log"
run_pread datafs-pread-odirect -d
run_pread datafs-pread
echo "datafs benchmark: starting raw-http" | tee -a "$workdir/benchmark.log"
/usr/bin/time -f 'raw-http elapsed_s=%e' \
	curl -fsS --range "0-$((length - 1))" \
	"http://$server/$bucket/$object" -o /dev/null \
	2>&1 | tee -a "$workdir/benchmark.log"

kill "$loader_pid"
wait "$loader_pid"
loader_pid=
mountpoint -q "$mountpoint" && fail "loader teardown left datafs mounted"
if dmesg | grep -E 'BUG:|WARNING: CPU|Oops:|general protection fault|KASAN:|UBSAN:'; then
	fail "kernel diagnostics contain a fatal warning"
fi
echo "datafs benchmark: PASS"
