#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -eEuo pipefail

mode=${1:-nfs}
server=${2:-}
arg=${3:-}
object=${4:-}
zcrx_if=${5:-}
network_if=${6:-}
network_mtu=${7:-}
mountpoint=/tmp/tcpfs-smoke-mnt
probe_mountpoint=/tmp/tcpfs-smoke-probe
workdir=/tmp/tcpfs-smoke
loader_pid=
server_pid=

fail()
{
	echo "tcpfs smoke: FAIL: $*" >&2
	exit 1
}

configure_network()
{
	local actual host overhead payload
	local -a ping_family=()

	[[ -n $network_if ]] || return 0
	[[ $network_mtu =~ ^[0-9]+$ ]] || fail "invalid MTU: $network_mtu"
	(( network_mtu >= 68 && network_mtu <= 65535 )) ||
		fail "MTU is outside the IPv4 interface range: $network_mtu"

	ip link set dev "$network_if" mtu "$network_mtu" ||
		fail "cannot set $network_if MTU to $network_mtu"
	actual=$(<"/sys/class/net/$network_if/mtu")
	[[ $actual == "$network_mtu" ]] ||
		fail "$network_if MTU is $actual, expected $network_mtu"

	[[ $mode == s3 && $network_mtu -gt 1500 ]] || return 0
	if [[ $server == \[*\]:* ]]; then
		host=${server#\[}
		host=${host%%\]*}
		overhead=48
		ping_family=(-6)
	else
		host=${server%:*}
		overhead=28
	fi
	payload=$((network_mtu - overhead))
	ping "${ping_family[@]}" -n -c 1 -W 2 -M do -s "$payload" \
		"$host" >/dev/null ||
		fail "$network_mtu-byte path MTU check to $host failed"
	echo "tcpfs smoke: network interface=$network_if mtu=$network_mtu"
}

cleanup()
{
	local rc=$?
	local log

	set +e
	mountpoint -q "$probe_mountpoint" && umount "$probe_mountpoint"
	mountpoint -q "$mountpoint" && umount "$mountpoint"
	if [[ -n $loader_pid ]]; then
		kill "$loader_pid" 2>/dev/null
		wait "$loader_pid" 2>/dev/null
	fi
	if [[ -n $server_pid ]]; then
		kill "$server_pid" 2>/dev/null
		wait "$server_pid" 2>/dev/null
	fi
	rmmod tcpfs 2>/dev/null
	if (( rc )); then
		shopt -s nullglob
		for log in "$workdir"/*.log; do
			echo "--- ${log##*/} ---" >&2
			cat "$log" >&2
		done
		shopt -u nullglob
		echo "--- dmesg ---" >&2
		dmesg >&2
	fi
	return "$rc"
}
trap cleanup EXIT

stop_server()
{
	if [[ -n $server_pid ]]; then
		kill "$server_pid"
		wait "$server_pid"
		server_pid=
	fi
}

wait_for_file()
{
	local file=$1
	local pid=$2
	local count

	for ((count = 0; count < 100; count++)); do
		[[ -s $file ]] && return 0
		kill -0 "$pid" 2>/dev/null || return 1
		sleep 0.05
	done
	return 1
}

wait_for_log()
{
	local pattern=$1
	local file=$2
	local pid=$3
	local count

	for ((count = 0; count < 100; count++)); do
		grep -q "$pattern" "$file" 2>/dev/null && return 0
		kill -0 "$pid" 2>/dev/null || return 1
		sleep 0.05
	done
	return 1
}

assert_clean_kernel()
{
	local pattern='BUG:|WARNING: CPU|Oops:|general protection fault|kernel BUG'

	pattern+='|KASAN:|UBSAN:|KFENCE:|refcount_t:|use-after-free|double free'
	pattern+='|kernel NULL pointer dereference|unable to handle kernel'
	pattern+='|possible circular locking dependency'
	pattern+='|sleeping function called from invalid context|scheduling while atomic'
	pattern+='|blocked for more than|corrupted list|list_(add|del) corruption'
	pattern+='|bad unlock balance|BUG: spinlock'

	if dmesg | grep -E "$pattern"; then
		fail "kernel diagnostics contain a fatal warning"
	fi
}

tcpfs_mount_options()
{
	local options="servers=$1,ops=$2,arg=$3,timeout_ms=$4"

	printf '%s,buf_size=4096,buf_count=8' "$options"
}

assert_mount_rejected()
{
	local description=$1
	local options=$2

	if mount -t tcpfs none "$probe_mountpoint" -o "$options" \
		>>"$workdir/rejected-mounts.log" 2>&1; then
		umount "$probe_mountpoint"
		fail "$description mount unexpectedly succeeded"
	fi
}

check_mount_validation()
{
	: >"$workdir/rejected-mounts.log"
	assert_mount_rejected "missing servers" \
		"ops=missing,timeout_ms=1"
	assert_mount_rejected "missing ops" \
		"servers=127.0.0.1:1,timeout_ms=1"
	assert_mount_rejected "malformed server" \
		"servers=not-an-address,ops=missing,timeout_ms=1"
	assert_mount_rejected "zero buffer size" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=1,buf_size=0"
	assert_mount_rejected "zero buffer count" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=1,buf_count=0"
	assert_mount_rejected "zero timeout" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=0"
	assert_mount_rejected "unknown option" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=1,unknown=1"
}

start_loader()
{
	local program=$1
	local ops=$2

	: >"$workdir/loader.log"
	"$program" >>"$workdir/loader.log" 2>&1 &
	loader_pid=$!
	wait_for_log "attached $ops" "$workdir/loader.log" "$loader_pid" ||
		fail "BPF loader did not attach $ops"
}

stop_loader()
{
	if [[ -n $loader_pid ]]; then
		kill "$loader_pid"
		wait "$loader_pid"
		loader_pid=
	fi
}

unload_tcpfs()
{
	local count

	for ((count = 0; count < 100; count++)); do
		if rmmod tcpfs 2>/dev/null; then
			return 0
		fi
		sleep 0.05
	done
	return 1
}

assert_duplicate_loader_rejected()
{
	local program=$1
	local rc

	set +e
	timeout 3 "$program" >"$workdir/duplicate-loader.log" 2>&1
	rc=$?
	set -e
	(( rc == 1 )) || fail "duplicate BPF loader returned $rc"
	grep -q "failed to attach struct_ops" "$workdir/duplicate-loader.log" ||
		fail "duplicate BPF loader failed for an unexpected reason"
}

run_parallel_reads()
{
	local path=$1
	local expected=$2
	local length=$3
	local count=$4
	local index pid
	local pids=()

	for ((index = 0; index < count; index++)); do
		(
			head -c "$length" "$path" >"$workdir/parallel.$index.data"
			cmp "$expected" "$workdir/parallel.$index.data"
		) >"$workdir/parallel.$index.log" 2>&1 &
		pids+=("$!")
	done
	for pid in "${pids[@]}"; do
		wait "$pid" || fail "parallel buffered read failed"
	done
}

run_parallel_uring()
{
	local path=$1
	local length=$2
	local count=$3
	local index pid
	local pids=()

	for ((index = 0; index < count; index++)); do
		(
			run_uring_check "$path" "$length" \
				"$workdir/uring-parallel.$index.log" 0 "$length"
		) &
		pids+=("$!")
	done
	for pid in "${pids[@]}"; do
		wait "$pid" || fail "parallel io_uring read failed"
	done
}

assert_read_only()
{
	local existing=$1
	local options

	options=$(findmnt -n -o OPTIONS "$mountpoint")
	[[ ,$options, == *,ro,* ]] || fail "mount is not marked read-only"
	if touch "$mountpoint/should-not-exist" 2>/dev/null; then
		fail "write unexpectedly succeeded"
	fi
	if { printf 'tcpfs write probe\n' >"$existing"; } 2>/dev/null; then
		fail "existing file write unexpectedly succeeded"
	fi
	if truncate -s 0 "$existing" 2>/dev/null; then
		fail "existing file truncate unexpectedly succeeded"
	fi
}

run_uring_check()
{
	local path=$1
	local length=$2
	local output=$3
	local offset=${4:-0}
	local expected=${5:-$length}
	local args=(-p "$path" -l "$length" -o "$offset")
	local copy_bytes fragments source stats

	if [[ -n $zcrx_if ]]; then
		args+=(-I "$zcrx_if" -q 0)
	fi
	./tcpfs_tools/tcpfs_uring_read_smoke "${args[@]}" >"$output" 2>&1 ||
		fail "io_uring zero-copy comparison failed"
	grep -q "comparison ok" "$output" ||
		fail "io_uring smoke did not report a successful comparison"
	grep -q "uring_cmd total=$expected" "$output" ||
		fail "io_uring smoke returned an unexpected byte count"
	source=${zcrx_if:-NODEV}
	grep -Fqx "zcrx source=$source rxq=0" "$output" ||
		fail "io_uring smoke used an unexpected ZCRX source"
	stats=$(grep -E '^zcrx copies=[0-9]+ bytes=[0-9]+$' "$output") ||
		fail "io_uring smoke did not report copy statistics"
	[[ $stats =~ ^zcrx\ copies=([0-9]+)\ bytes=([0-9]+)$ ]] ||
		fail "io_uring smoke reported malformed copy statistics"
	copy_bytes=${BASH_REMATCH[2]}
	fragments=$(sed -n 's/^zcrx fragments=\([0-9][0-9]*\)$/\1/p' "$output")
	[[ -n $fragments ]] || fail "io_uring smoke did not report fragments"
	if (( expected > 0 )); then
		(( fragments > 0 )) ||
			fail "io_uring smoke did not observe a data completion"
		if (( expected > 4096 )); then
			(( fragments > 1 )) ||
				fail "io_uring smoke did not exercise multishot completions"
		fi
	fi
	if [[ -n $zcrx_if ]]; then
		if (( expected > 0 )); then
			(( copy_bytes < expected )) ||
				fail "NIC ZCRX copied the entire response"
		fi
	else
		(( copy_bytes == expected )) ||
			fail "NODEV ZCRX copy accounting is incomplete"
	fi
}

run_nfs()
{
	local listing expected_listing options requests

	server=${server:-127.0.0.1:20490}
	arg=${arg:-export}
	python3 ./tcpfs_tools/tcpfs_nfs_test_server.py \
		--write-expected "$workdir/direct.expected"
	python3 -u ./tcpfs_tools/tcpfs_nfs_test_server.py \
		--address "${server%:*}" --port "${server##*:}" \
		--ready-file "$workdir/server.ready" \
		>"$workdir/server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$workdir/server.ready" "$server_pid" ||
		fail "NFS fixture server did not become ready"

	start_loader ./tcpfs_tools/tcpfs_nfs_loader tcpfs_nfs
	assert_duplicate_loader_rejected ./tcpfs_tools/tcpfs_nfs_loader
	options=$(tcpfs_mount_options "$server" tcpfs_nfs "$arg" 5000)
	mount -t tcpfs none "$mountpoint" -o "$options"
	[[ $(findmnt -n -o FSTYPE "$mountpoint") == tcpfs ]] ||
		fail "mount is not tcpfs"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=tcpfs_nfs' ||
		fail "NFS BPF ops are absent from reported mount options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq "arg=$arg" ||
		fail "NFS argument is absent from reported mount options"

	listing=$(LC_ALL=C ls -1 "$mountpoint")
	expected_listing=$'direct.bin\nempty.txt\nhello.txt\nnested\nslow.bin'
	[[ $listing == "$expected_listing" ]] ||
		fail "unexpected root listing: $listing"
	[[ $(LC_ALL=C ls -1 "$mountpoint/nested") == note.txt ]] ||
		fail "unexpected nested listing"

	printf 'hello from tcpfs nfs\n' >"$workdir/hello.expected"
	printf 'nested tcpfs nfs file\n' >"$workdir/note.expected"
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "buffered hello read differs"
	cmp "$workdir/note.expected" "$mountpoint/nested/note.txt" ||
		fail "nested buffered read differs"
	cat "$mountpoint/empty.txt" >"$workdir/empty.data"
	[[ ! -s $workdir/empty.data ]] || fail "empty file returned data"
	[[ $(stat -c %s "$mountpoint/direct.bin") == 8192 ]] ||
		fail "NFS getattr returned the wrong size"
	[[ $(stat -c %s "$mountpoint/empty.txt") == 0 ]] ||
		fail "empty file size is not zero"
	[[ $(stat -c %a "$mountpoint/hello.txt") == 444 ]] ||
		fail "regular file mode is not read-only"
	[[ $(stat -c %a "$mountpoint/nested") == 555 ]] ||
		fail "directory mode is not read-only"
	if stat "$mountpoint/missing" >/dev/null 2>&1; then
		fail "missing NFS path unexpectedly resolved"
	fi

	cat "$mountpoint/direct.bin" >"$workdir/direct.buffered"
	cmp "$workdir/direct.expected" "$workdir/direct.buffered" ||
		fail "buffered NFS data differs"
	run_parallel_reads "$mountpoint/direct.bin" \
		"$workdir/direct.expected" 8192 8
	dd if="$mountpoint/direct.bin" of="$workdir/direct.odirect" \
		iflag=direct bs=4096 count=2 status=none
	cmp "$workdir/direct.expected" "$workdir/direct.odirect" ||
		fail "O_DIRECT NFS data differs"
	dd if="$mountpoint/direct.bin" of="$workdir/direct.offset" \
		iflag=direct bs=4096 skip=1 count=1 status=none
	dd if="$workdir/direct.expected" of="$workdir/direct.offset.expected" \
		bs=4096 skip=1 count=1 status=none
	cmp "$workdir/direct.offset.expected" "$workdir/direct.offset" ||
		fail "offset O_DIRECT NFS data differs"

	run_uring_check "$mountpoint/direct.bin" 8192 "$workdir/uring.log" 0 8192
	run_uring_check "$mountpoint/direct.bin" 4096 \
		"$workdir/uring-offset.log" 4096 4096
	run_uring_check "$mountpoint/direct.bin" 12288 \
		"$workdir/uring-eof.log" 0 8192
	run_uring_check "$mountpoint/empty.txt" 4096 \
		"$workdir/uring-empty.log" 0 0
	run_parallel_uring "$mountpoint/direct.bin" 8192 4
	./tcpfs_tools/tcpfs_uring_read_smoke -C \
		-p "$mountpoint/slow.bin" -l 8192 >"$workdir/uring-cancel.log" 2>&1 ||
		fail "io_uring cancellation smoke failed"
	grep -q "cancellation command=-125 cancel=0" \
		"$workdir/uring-cancel.log" ||
		fail "io_uring cancellation returned unexpected results"
	wait_for_log 'response delayed path=/export/slow.bin' \
		"$workdir/server.log" "$server_pid" ||
		fail "NFS fixture did not observe the cancellable read"
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "read after io_uring cancellation differs"
	assert_read_only "$mountpoint/hello.txt"

	requests=$(grep -c '^request peer=' "$workdir/server.log" || true)
	(( requests >= 12 )) || fail "fixture observed only $requests requests"
	if grep -q '^request error:' "$workdir/server.log"; then
		fail "NFS fixture rejected a request"
	fi
	grep -q 'path=/export ops=24,15,26' "$workdir/server.log" ||
		fail "fixture did not observe a root READDIR compound"
	grep -q 'path=/export/direct.bin ops=24,15,15,25' \
		"$workdir/server.log" ||
		fail "fixture did not observe a file READ compound"
	grep -Eq 'response path=/export/direct.bin .*fragments=([2-9]|[1-9][0-9]+)' \
		"$workdir/server.log" ||
		fail "fixture did not fragment a file response"

	# Existing mounts pin detached struct_ops maps; new mounts cannot find them.
	stop_loader
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "read after BPF loader exit differs"
	options=$(tcpfs_mount_options "$server" tcpfs_nfs "$arg" 50)
	if mount -t tcpfs none "$probe_mountpoint" -o "$options" \
		>"$workdir/detached-mount.log" 2>&1; then
		umount "$probe_mountpoint"
		fail "detached BPF ops accepted a new mount"
	fi

	# Exercise module teardown and mount again with a fresh BPF link.
	umount "$mountpoint"
	unload_tcpfs || fail "tcpfs remained busy after BPF detach and unmount"
	modprobe tcpfs
	start_loader ./tcpfs_tools/tcpfs_nfs_loader tcpfs_nfs
	options=$(tcpfs_mount_options "$server" tcpfs_nfs "$arg" 5000)
	mount -t tcpfs none "$mountpoint" -o "$options"
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "read after module reload differs"
	umount "$mountpoint"
	options=$(tcpfs_mount_options "$server" tcpfs_nfs "$arg/nested" 5000)
	mount -t tcpfs none "$mountpoint" -o "$options"
	[[ $(LC_ALL=C ls -1 "$mountpoint") == note.txt ]] ||
		fail "nested NFS mount argument returned the wrong listing"
	cmp "$workdir/note.expected" "$mountpoint/note.txt" ||
		fail "nested NFS mount argument returned the wrong data"
}

run_s3()
{
	local endpoint basename length options remote_size

	[[ -n $server && -n $arg && -n $object ]] ||
		fail "s3 mode requires SERVER BUCKET OBJECT"
	endpoint="http://$server/$arg/$object"
	basename=${object##*/}
	curl -fsS --range 0-8191 "$endpoint" >"$workdir/s3.expected" ||
		fail "could not fetch S3 reference data"
	curl -fsSI "$endpoint" >"$workdir/s3.head" ||
		fail "could not fetch S3 object metadata"
	length=$(stat -c %s "$workdir/s3.expected")
	(( length == 8192 )) || fail "S3 range request returned $length bytes"
	remote_size=$(awk 'tolower($1) == "content-length:" {
		gsub("\\r", "", $2); print $2; exit
	}' "$workdir/s3.head")
	[[ $remote_size =~ ^[0-9]+$ ]] || fail "S3 Content-Length is missing"
	(( remote_size >= length )) || fail "S3 object is shorter than the fixture read"

	start_loader ./tcpfs_tools/tcpfs_s3_loader tcpfs_s3
	assert_duplicate_loader_rejected ./tcpfs_tools/tcpfs_s3_loader
	options=$(tcpfs_mount_options "$server" tcpfs_s3 "$arg" 5000)
	mount -t tcpfs none "$mountpoint" -o "$options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=tcpfs_s3' ||
		fail "S3 BPF ops are absent from reported mount options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq "arg=$arg" ||
		fail "S3 argument is absent from reported mount options"
	LC_ALL=C ls -1 "$mountpoint" | grep -Fxq "$basename" ||
		fail "S3 listing does not contain $basename"
	[[ $(stat -c %s "$mountpoint/$object") == "$remote_size" ]] ||
		fail "S3 getattr returned the wrong object size"
	if stat "$mountpoint/$object.tcpfs-missing" >/dev/null 2>&1; then
		fail "missing S3 object unexpectedly resolved"
	fi
	dd if="$mountpoint/$object" of="$workdir/s3.buffered" \
		bs="$length" count=1 status=none
	cmp "$workdir/s3.expected" "$workdir/s3.buffered" ||
		fail "buffered S3 data differs"
	run_parallel_reads "$mountpoint/$object" "$workdir/s3.expected" \
		"$length" 4
	dd if="$mountpoint/$object" of="$workdir/s3.odirect" \
		iflag=direct bs=4096 count=$(((length + 4095) / 4096)) status=none
	cmp "$workdir/s3.expected" "$workdir/s3.odirect" ||
		fail "O_DIRECT S3 data differs"
	dd if="$mountpoint/$object" of="$workdir/s3.offset" \
		iflag=direct bs=4096 skip=1 count=1 status=none
	dd if="$workdir/s3.expected" of="$workdir/s3.offset.expected" \
		bs=4096 skip=1 count=1 status=none
	cmp "$workdir/s3.offset.expected" "$workdir/s3.offset" ||
		fail "offset O_DIRECT S3 data differs"
	run_uring_check "$mountpoint/$object" "$length" "$workdir/uring.log" \
		0 "$length"
	run_uring_check "$mountpoint/$object" 4096 \
		"$workdir/uring-offset.log" 4096 4096
	run_uring_check "$mountpoint/$object" 4096 \
		"$workdir/uring-eof.log" "$remote_size" 0
	assert_read_only "$mountpoint/$object"
}

rm -rf "$workdir"
mkdir -p "$workdir" "$mountpoint" "$probe_mountpoint"
dmesg -C
mkdir -p /sys/kernel/debug
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
modprobe tcpfs
if [[ -w /sys/kernel/debug/dynamic_debug/control ]]; then
	echo 'module tcpfs +p' > /sys/kernel/debug/dynamic_debug/control
fi
grep -qw tcpfs /proc/filesystems || fail "tcpfs is not registered"
[[ -d /sys/module/tcpfs ]] || fail "tcpfs module is absent from sysfs"
check_mount_validation

configure_network

if [[ -n $zcrx_if ]]; then
	ethtool -K "$zcrx_if" rx-gro-hw off
	ethtool -G "$zcrx_if" tcp-data-split on
fi

case $mode in
nfs)
	run_nfs
	;;
s3)
	run_s3
	;;
*)
	fail "unknown mode $mode"
	;;
esac

umount "$mountpoint"
stop_loader
stop_server
unload_tcpfs || fail "tcpfs remained busy during final teardown"
[[ ! -d /sys/module/tcpfs ]] || fail "tcpfs module remained in sysfs"
if grep -qw tcpfs /proc/filesystems; then
	fail "tcpfs remained registered after module unload"
fi
assert_clean_kernel
echo "tcpfs smoke: PASS mode=$mode zcrx=${zcrx_if:-NODEV} mtu=${network_mtu:-default}"
