#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

TOOLS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BENCH="${BENCH:-$TOOLS_DIR/tcpfs_bench_read}"

TCPFS_MNT="${TCPFS_MNT:-/tmp/tcpfs}"
FUSE_MNT="${FUSE_MNT:-}"
FILE="${FILE:-links.txt}"
LEN="${LEN:-4096}"
ITERS="${ITERS:-100}"
WARMUP="${WARMUP:-5}"
CSV="${CSV:-0}"
ZCRX_IF="${ZCRX_IF:-}"
ZCRX_RXQ="${ZCRX_RXQ:-0}"
MTU="${MTU:-8000}"

usage()
{
	cat >&2 <<EOF
usage: $0 [options]

Options:
  --tcpfs-mnt DIR    mounted tcpfs directory (default: $TCPFS_MNT)
  --fuse-mnt DIR     mounted S3 FUSE directory to compare
  --file PATH        file path relative to each mount (default: $FILE)
  --len BYTES        bytes per read (default: $LEN)
  --iters N          measured iterations (default: $ITERS)
  --warmup N         warmup iterations (default: $WARMUP)
  --zcrx-if IFACE    bind uring ZCRX to this receive interface
  --zcrx-rxq N       receive queue used with --zcrx-if (default: $ZCRX_RXQ)
  --mtu BYTES        require this MTU on --zcrx-if (default: $MTU)
  --csv              emit CSV from each benchmark

Environment:
  FUSE_MNT can point at an existing s3fs/goofys/rclone mount.
  FUSE_MOUNT_CMD can contain a command to create that mount before running.
  ZCRX_IF selects NIC ZCRX; leaving it empty runs the NODEV backend.

Example:
  FUSE_MOUNT_CMD='s3fs publicbucket /tmp/s3fs -o url=http://192.168.1.238:9000 -o use_path_request_style -o passwd_file=/root/.passwd-s3fs' \\
  FUSE_MNT=/tmp/s3fs $0 --file links.txt --len 2127 --iters 1000 --csv
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--tcpfs-mnt)
		TCPFS_MNT="$2"
		shift 2
		;;
	--fuse-mnt)
		FUSE_MNT="$2"
		shift 2
		;;
	--file)
		FILE="$2"
		shift 2
		;;
	--len)
		LEN="$2"
		shift 2
		;;
	--iters)
		ITERS="$2"
		shift 2
		;;
	--warmup)
		WARMUP="$2"
		shift 2
		;;
	--zcrx-if)
		ZCRX_IF="$2"
		shift 2
		;;
	--zcrx-rxq)
		ZCRX_RXQ="$2"
		shift 2
		;;
	--mtu)
		MTU="$2"
		shift 2
		;;
	--csv)
		CSV=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		usage
		exit 2
		;;
	esac
done

if [ ! -x "$BENCH" ]; then
	echo "benchmark binary not found: $BENCH" >&2
	exit 1
fi

if [ -n "$ZCRX_IF" ]; then
	case "$MTU" in
	''|*[!0-9]*)
		echo "invalid MTU: $MTU" >&2
		exit 2
		;;
	esac
	case "$ZCRX_RXQ" in
	''|*[!0-9]*)
		echo "invalid receive queue: $ZCRX_RXQ" >&2
		exit 2
		;;
	esac
	actual=$(cat "/sys/class/net/$ZCRX_IF/mtu")
	if [ "$actual" != "$MTU" ]; then
		echo "$ZCRX_IF MTU is $actual, expected $MTU" >&2
		exit 1
	fi
fi

if [ -n "${FUSE_MOUNT_CMD:-}" ]; then
	sh -c "$FUSE_MOUNT_CMD"
fi

run()
{
	label="$1"
	path="$2"
	mode="$3"
	direct="$4"

	set -- -p "$path" -m "$mode" -l "$LEN" -i "$ITERS" -w "$WARMUP" \
		-L "$label"
	if [ "$direct" = 1 ]; then
		set -- "$@" -d
	fi
	if [ "$mode" = uring ] && [ -n "$ZCRX_IF" ]; then
		set -- "$@" -I "$ZCRX_IF" -q "$ZCRX_RXQ"
	fi
	if [ "$CSV" = 1 ]; then
		set -- "$@" -c
	fi
	"$BENCH" "$@"
}

run tcpfs-uring "$TCPFS_MNT/$FILE" uring 1
run tcpfs-pread-odirect "$TCPFS_MNT/$FILE" pread 1
run tcpfs-pread "$TCPFS_MNT/$FILE" pread 0

if [ -n "$FUSE_MNT" ]; then
	run s3-fuse-pread "$FUSE_MNT/$FILE" pread 0
	if "$BENCH" -p "$FUSE_MNT/$FILE" -m pread -l "$LEN" -i 1 -w 0 \
		-d -L s3-fuse-odirect-probe >/dev/null 2>&1; then
		run s3-fuse-pread-odirect "$FUSE_MNT/$FILE" pread 1
	else
		echo "s3-fuse-pread-odirect skipped: O_DIRECT unsupported by $FUSE_MNT/$FILE" >&2
	fi
fi
