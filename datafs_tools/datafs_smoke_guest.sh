#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -eEuo pipefail

mode=${1:-datafs-nfs}
server=${2:-}
arg=${3:-}
object=${4:-}
devmem_if=${5:-}
network_if=${6:-}
network_mtu=${7:-}
mountpoint=/tmp/datafs-smoke-mnt
probe_mountpoint=/tmp/datafs-smoke-probe
workdir=/tmp/datafs-smoke
loader_pid=
server_pid=

fail()
{
	echo "datafs smoke: FAIL: $*" >&2
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

	[[ $mode == s3* || $mode == datafs-s3* ]] || return 0
	(( network_mtu > 1500 )) || return 0
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
	echo "datafs smoke: network interface=$network_if mtu=$network_mtu"
}

cleanup()
{
	local rc=$?
	local log

	set +e
	mountpoint -q "$probe_mountpoint" && umount "$probe_mountpoint"
	mountpoint -q "$mountpoint" && umount "$mountpoint"
	rmmod datafs 2>/dev/null
	if [[ -n $loader_pid ]]; then
		kill "$loader_pid" 2>/dev/null
		wait "$loader_pid" 2>/dev/null
	fi
	if [[ -n $server_pid ]]; then
		kill "$server_pid" 2>/dev/null
		wait "$server_pid" 2>/dev/null
	fi
	rmmod datafs 2>/dev/null
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
		wait "$server_pid" || true
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

datafs_mount_options()
{
	local options="servers=$1,ops=$2,arg=$3,timeout_ms=$4"

	printf '%s,buf_size=4096,pool_size=8' "$options"
}

assert_mount_rejected()
{
	local description=$1
	local options=$2

	if mount -t datafs none "$probe_mountpoint" -o "$options" \
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
	assert_mount_rejected "zero pool size" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=1,pool_size=0"
	assert_mount_rejected "zero timeout" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=0"
	assert_mount_rejected "unknown option" \
		"servers=127.0.0.1:1,ops=missing,timeout_ms=1,unknown=1"
}

start_loader()
{
	local program=$1
	local ops=$2
	shift 2

	: >"$workdir/loader.log"
	"$program" "$@" >>"$workdir/loader.log" 2>&1 &
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

unload_datafs()
{
	local count

	for ((count = 0; count < 100; count++)); do
		if rmmod datafs 2>/dev/null; then
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

assert_struct_ops_rejected()
{
	local object=$1
	local map=$2
	local rc

	set +e
	timeout 3 ./datafs_tools/datafs_nfs_loader "$object" "$map" \
		>"$workdir/rejected-$map.log" 2>&1
	rc=$?
	set -e
	(( rc == 1 )) || fail "$map BPF loader returned $rc"
	grep -q "failed to attach struct_ops" "$workdir/rejected-$map.log" ||
		fail "$map BPF loader failed for an unexpected reason"
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

run_io_uring_read()
{
	local path=$1
	local expected=$2
	local length=$3
	local offset=${4:-0}

	timeout 10 ./datafs_tools/datafs_uring_read \
		--path "$path" --expected "$expected" --length "$length" \
		--offset "$offset" >"$workdir/io-uring-read.log" 2>&1 ||
		fail "io_uring read failed"
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
	if { printf 'datafs write probe\n' >"$existing"; } 2>/dev/null; then
		fail "existing file write unexpectedly succeeded"
	fi
	if truncate -s 0 "$existing" 2>/dev/null; then
		fail "existing file truncate unexpectedly succeeded"
	fi
}

run_datafs_nfs()
{
	local listing options peers requests

	server=${server:-127.0.0.1:20490}
	arg=${arg:-export}
	./datafs_tools/datafs_nfs_test_server \
		--write-expected "$workdir/direct.expected"
	./datafs_tools/datafs_nfs_test_server \
		--address "${server%:*}" --port "${server##*:}" \
		--ready-file "$workdir/server.ready" \
		>"$workdir/server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$workdir/server.ready" "$server_pid" ||
		fail "NFS fixture server did not become ready"

	start_loader ./datafs_tools/datafs_nfs_loader datafs_nfs_serial \
		./datafs_tools/datafs_nfs_serial.bpf.o datafs_nfs_serial
	options=$(datafs_mount_options "$server" datafs_nfs_serial "$arg" 5000)
	mount -t datafs none "$mountpoint" -o "$options"
	[[ $(findmnt -n -o FSTYPE "$mountpoint") == datafs ]] ||
		fail "mount is not datafs"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=datafs_nfs_serial' ||
		fail "NFS BPF ops are absent from datafs mount options"

	listing=$(LC_ALL=C ls -1 "$mountpoint")
	[[ $listing == $'direct.bin\nempty.txt\nhello.txt\nnested\nslow.bin' ]] ||
		fail "unexpected datafs root listing: $listing"
	[[ $(LC_ALL=C ls -1 "$mountpoint/nested") == note.txt ]] ||
		fail "unexpected datafs nested listing"
	printf 'hello from datafs nfs\n' >"$workdir/hello.expected"
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "datafs buffered read differs"
	cat "$mountpoint/empty.txt" >"$workdir/empty.data"
	[[ ! -s $workdir/empty.data ]] || fail "datafs empty file returned data"
	[[ $(stat -c %s "$mountpoint/direct.bin") == 8192 ]] ||
		fail "datafs getattr returned the wrong size"
	cat "$mountpoint/direct.bin" >"$workdir/direct.buffered"
	cmp "$workdir/direct.expected" "$workdir/direct.buffered" ||
		fail "datafs buffered data differs"
	run_io_uring_read "$mountpoint/direct.bin" \
		"$workdir/direct.expected" 8192
	run_parallel_reads "$mountpoint/direct.bin" \
		"$workdir/direct.expected" 8192 8
	dd if="$mountpoint/direct.bin" of="$workdir/direct.odirect" \
		iflag=direct bs=4096 count=2 status=none
	cmp "$workdir/direct.expected" "$workdir/direct.odirect" ||
		fail "datafs O_DIRECT data differs"
	dd if="$mountpoint/direct.bin" of="$workdir/direct.offset" \
		iflag=direct bs=4096 skip=1 count=1 status=none
	dd if="$workdir/direct.expected" of="$workdir/direct.offset.expected" \
		bs=4096 skip=1 count=1 status=none
	cmp "$workdir/direct.offset.expected" "$workdir/direct.offset" ||
		fail "datafs offset O_DIRECT data differs"
	assert_read_only "$mountpoint/hello.txt"
	requests=$(grep -c '^request peer=' "$workdir/server.log" || true)
	peers=$(sed -n 's/^request peer=\([^ ]*\).*/\1/p' \
		"$workdir/server.log" | sort -u | wc -l)
	(( requests > peers && peers <= 8 )) ||
		fail "datafs serial pool did not reuse connections ($requests requests, $peers peers)"
}

run_smb()
{
	local listing options requests

	server=${server:-127.0.0.1:20445}
	arg=${arg:-SERVER/public}
	./datafs_tools/datafs_smb_test_server \
		--write-expected "$workdir/direct.expected"
	./datafs_tools/datafs_smb_test_server \
		--address "${server%:*}" --port "${server##*:}" \
		--ready-file "$workdir/server.ready" \
		>"$workdir/server.log" 2>&1 &
	server_pid=$!
	wait_for_file "$workdir/server.ready" "$server_pid" ||
		fail "SMB fixture server did not become ready"

	start_loader ./datafs_tools/datafs_smb_loader datafs_smb
	assert_duplicate_loader_rejected ./datafs_tools/datafs_smb_loader
	options=$(datafs_mount_options "$server" datafs_smb "$arg" 5000)
	mount -t datafs none "$mountpoint" -o "$options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=datafs_smb' ||
		fail "SMB BPF ops are absent from reported mount options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq "arg=$arg" ||
		fail "SMB argument is absent from reported mount options"

	listing=$(LC_ALL=C ls -1 "$mountpoint")
	[[ $listing == $'direct.bin\nhello.txt\nnested' ]] ||
		fail "unexpected SMB root listing: $listing"
	[[ $(LC_ALL=C ls -1 "$mountpoint/nested") == note.txt ]] ||
		fail "unexpected SMB nested listing"
	printf 'hello from datafs smb\n' >"$workdir/hello.expected"
	printf 'nested datafs smb file\n' >"$workdir/note.expected"
	cmp "$workdir/hello.expected" "$mountpoint/hello.txt" ||
		fail "buffered SMB hello read differs"
	cmp "$workdir/note.expected" "$mountpoint/nested/note.txt" ||
		fail "nested buffered SMB read differs"
	[[ $(stat -c %s "$mountpoint/direct.bin") == 8192 ]] ||
		fail "SMB getattr returned the wrong size"
	[[ $(stat -c %a "$mountpoint/hello.txt") == 444 ]] ||
		fail "SMB file mode is not read-only"
	[[ $(stat -c %a "$mountpoint/nested") == 555 ]] ||
		fail "SMB directory mode is not read-only"
	if stat "$mountpoint/missing" >/dev/null 2>&1; then
		fail "missing SMB path unexpectedly resolved"
	fi

	cat "$mountpoint/direct.bin" >"$workdir/direct.buffered"
	cmp "$workdir/direct.expected" "$workdir/direct.buffered" ||
		fail "buffered SMB data differs"
	run_io_uring_read "$mountpoint/direct.bin" \
		"$workdir/direct.expected" 8192
	dd if="$mountpoint/direct.bin" of="$workdir/direct.odirect" \
		iflag=direct bs=4096 count=2 status=none
	cmp "$workdir/direct.expected" "$workdir/direct.odirect" ||
		fail "O_DIRECT SMB data differs"
	dd if="$mountpoint/direct.bin" of="$workdir/direct.offset" \
		iflag=direct bs=4096 skip=1 count=1 status=none
	dd if="$workdir/direct.expected" of="$workdir/direct.offset.expected" \
		bs=4096 skip=1 count=1 status=none
	cmp "$workdir/direct.offset.expected" "$workdir/direct.offset" ||
		fail "offset O_DIRECT SMB data differs"
	assert_read_only "$mountpoint/hello.txt"

	requests=$(grep -c '^request peer=' "$workdir/server.log" || true)
	(( requests >= 25 )) || fail "SMB fixture observed only $requests requests"
	grep -q 'command=0' "$workdir/server.log" ||
		fail "SMB fixture did not observe NEGOTIATE"
	grep -q 'command=14' "$workdir/server.log" ||
		fail "SMB fixture did not observe QUERY_DIRECTORY"
	grep -q 'command=8' "$workdir/server.log" ||
		fail "SMB fixture did not observe READ"
	if grep -q '^request error:' "$workdir/server.log"; then
		fail "SMB fixture rejected a request"
	fi
}

run_datafs_rest()
{
	local endpoint=127.0.0.1:18080
	local result
	local count

	PYTHONDONTWRITEBYTECODE=1 python3 -u \
		./datafs_tools/datafs_rest_example.py --host 127.0.0.1 --port 18080 \
		>"$workdir/rest-server.log" 2>&1 &
	server_pid=$!
	for ((count = 0; count < 100; count++)); do
		curl -fsS "http://$endpoint/openapi.json" >/dev/null 2>&1 && break
		kill -0 "$server_pid" 2>/dev/null || fail "REST example server exited"
		sleep 0.05
	done
	curl -fsS "http://$endpoint/openapi.json" >/dev/null ||
		fail "REST OpenAPI endpoint did not become ready"

	start_loader ./datafs_tools/datafs_rest_loader datafs_rest \
		--mount "$mountpoint" --server "$endpoint" --arg /v1
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=datafs_rest' ||
		fail "REST mount does not report its provider"
	ls -1a "$mountpoint" >"$workdir/rest-listing"
	grep -qx add "$workdir/rest-listing" || fail "REST add endpoint is absent"
	grep -qx multiply "$workdir/rest-listing" ||
		fail "REST multiply endpoint is absent"
	grep -qx .schema "$workdir/rest-listing" ||
		fail "REST schema directory is absent"

	result=$(cat "$mountpoint/add?a=40&b=2")
	[[ $result == '{"a":40,"b":2,"operation":"add","result":42}' ]] ||
		fail "REST query result is incorrect: $result"
	result=$(cat "$mountpoint/gcd?a=54&b=24")
	[[ $result == '{"a":54,"b":24,"operation":"gcd","result":6}' ]] ||
		fail "REST gcd result is incorrect: $result"
	grep -q '"operationId": "add"' "$mountpoint/.schema/add" ||
		fail "REST shadow schema does not contain the add operation"
	assert_read_only "$mountpoint/add?a=1&b=2"
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

	start_loader ./datafs_tools/datafs_s3_loader datafs_s3
	assert_duplicate_loader_rejected ./datafs_tools/datafs_s3_loader
	options=$(datafs_mount_options "$server" datafs_s3 "$arg" 5000)
	mount -t datafs none "$mountpoint" -o "$options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq 'ops=datafs_s3' ||
		fail "S3 BPF ops are absent from reported mount options"
	findmnt -n -o OPTIONS "$mountpoint" | grep -Fq "arg=$arg" ||
		fail "S3 argument is absent from reported mount options"
	LC_ALL=C ls -1 "$mountpoint" | grep -Fxq "$basename" ||
		fail "S3 listing does not contain $basename"
	[[ $(stat -c %s "$mountpoint/$object") == "$remote_size" ]] ||
		fail "S3 getattr returned the wrong object size"
	if stat "$mountpoint/$object.datafs-missing" >/dev/null 2>&1; then
		fail "missing S3 object unexpectedly resolved"
	fi
	dd if="$mountpoint/$object" of="$workdir/s3.buffered" \
		bs="$length" count=1 status=none
	cmp "$workdir/s3.expected" "$workdir/s3.buffered" ||
		fail "buffered S3 data differs"
	run_io_uring_read "$mountpoint/$object" "$workdir/s3.expected" "$length"
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
	assert_read_only "$mountpoint/$object"
}

run_datafs_s3_devmem()
{
	local endpoint length remote_size

	[[ -n $server && -n $arg && -n $object && -n $devmem_if ]] ||
		fail "datafs-s3-devmem mode requires SERVER BUCKET OBJECT IFACE"
	endpoint="http://$server/$arg/$object"
	curl -fsSI "$endpoint" >"$workdir/s3.head" ||
		fail "could not fetch S3 object metadata"
	remote_size=$(awk 'tolower($1) == "content-length:" {
		gsub("\\r", "", $2); print $2; exit
	}' "$workdir/s3.head")
	[[ $remote_size =~ ^[0-9]+$ ]] || fail "S3 Content-Length is missing"
	length=$((8 * 1024 * 1024))
	(( remote_size >= length )) ||
		fail "datafs devmem fixture must be at least $length bytes"
	curl -fsS --range "0-$((length - 1))" "$endpoint" \
		>"$workdir/s3.expected" || fail "could not fetch S3 reference data"
	[[ $(stat -c %s "$workdir/s3.expected") == "$length" ]] ||
		fail "S3 range request did not return $length bytes"

	if [[ ! -c /dev/udmabuf ]]; then
		modprobe udmabuf 2>/dev/null || true
	fi
	[[ -c /dev/udmabuf ]] || fail "udmabuf device is unavailable"
	: >"$workdir/loader.log"
	./datafs_tools/datafs_s3_loader \
		--mount "$mountpoint" --server "$server" --arg "$arg" \
		--loan-sockets 1 \
		>>"$workdir/loader.log" 2>&1 &
	loader_pid=$!
	wait_for_log "mounted datafs" "$workdir/loader.log" "$loader_pid" ||
		fail "BPF loader did not mount socket-loan datafs"
	[[ $(findmnt -n -o FSTYPE "$mountpoint") == datafs ]] ||
		fail "queue-backed mount is not datafs"
	[[ $(stat -c %s "$mountpoint/$object") == "$remote_size" ]] ||
		fail "datafs S3 getattr returned the wrong size"

	for iteration in 1 2; do
		timeout 20 ./datafs_tools/datafs_devmem_smoke \
			--path "$mountpoint/$object" --expected "$workdir/s3.expected" \
			--length "$length" --iface "$devmem_if" --rxq 0 \
			--require-devmem >"$workdir/datafs-devmem.$iteration.log" ||
			fail "datafs devmem read $iteration failed"
	done
	grep -Eq 'dmabuf=[1-9][0-9]*' "$workdir/datafs-devmem.1.log" ||
		fail "datafs devmem smoke used only host fallback"
}

rm -rf "$workdir"
mkdir -p "$workdir" "$mountpoint" "$probe_mountpoint"
dmesg -C
mkdir -p /sys/kernel/debug
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
modprobe datafs
grep -qw datafs /proc/filesystems || fail "datafs is not registered"
[[ -d /sys/module/datafs ]] || fail "datafs module is absent from sysfs"
if [[ -w /sys/kernel/debug/dynamic_debug/control ]]; then
	echo 'module datafs +p' > /sys/kernel/debug/dynamic_debug/control
fi
check_mount_validation

configure_network

if [[ -n $devmem_if ]]; then
	if [[ $mode == datafs-s3-devmem ]]; then
		ethtool -L "$devmem_if" combined 1 ||
			fail "could not restrict $devmem_if to one combined queue"
	fi
	ethtool -K "$devmem_if" gro on ||
		fail "could not enable software GRO on $devmem_if"
	ethtool -k "$devmem_if" | grep -q '^generic-receive-offload: on' ||
		fail "software GRO is not enabled on $devmem_if"
	ethtool -K "$devmem_if" rx-gro-hw off
	ethtool -G "$devmem_if" tcp-data-split on
fi

case $mode in
datafs-nfs)
	run_datafs_nfs
	;;
datafs-rest)
	run_datafs_rest
	;;
datafs-smb)
	run_smb
	;;
datafs-s3)
	run_s3
	;;
datafs-s3-devmem)
	run_datafs_s3_devmem
	;;
*)
	fail "unknown mode $mode"
	;;
esac

mountpoint -q "$mountpoint" && umount "$mountpoint"
stop_loader
stop_server
unload_datafs || fail "datafs remained busy during final teardown"
[[ ! -d /sys/module/datafs ]] || fail "datafs module remained in sysfs"
if grep -qw datafs /proc/filesystems; then
	fail "datafs remained registered after module unload"
fi
assert_clean_kernel
echo "datafs smoke: PASS mode=$mode iface=${devmem_if:-none} mtu=${network_mtu:-default}"
