#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

TOOLS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SERVER="${SERVER:-192.168.1.238:9000}"
ARG="${ARG:-publicbucket}"
MNT="${MNT:-/tmp/datafs}"
TIMEOUT_MS="${TIMEOUT_MS:-5000}"
BUF_SIZE="${BUF_SIZE:-4096}"
BUF_COUNT="${BUF_COUNT:-8}"
LOAN_SOCKETS="${LOAN_SOCKETS:-0}"
LOADER_LOG="${LOADER_LOG:-/tmp/datafs-bench-loader.log}"

mkdir -p "$MNT"
modprobe datafs
if mountpoint -q "$MNT"; then
	echo "$MNT"
	exit 0
fi

: >"$LOADER_LOG"
set -- "$TOOLS_DIR/datafs_s3_loader" --mount "$MNT" --server "$SERVER" \
	--arg "$ARG" --timeout-ms "$TIMEOUT_MS" --buf-size "$BUF_SIZE" \
	--buf-count "$BUF_COUNT"
if [ "$LOAN_SOCKETS" -gt 0 ]; then
	set -- "$@" --loan-sockets "$LOAN_SOCKETS"
fi
"$@" >"$LOADER_LOG" 2>&1 &
loader_pid=$!
count=0
while ! mountpoint -q "$MNT"; do
	if ! kill -0 "$loader_pid" 2>/dev/null || [ "$count" -eq 100 ]; then
		kill "$loader_pid" 2>/dev/null || :
		wait "$loader_pid" 2>/dev/null || :
		cat "$LOADER_LOG" >&2
		echo "datafs mount did not become ready" >&2
		exit 1
	fi
	count=$((count + 1))
	sleep 0.05
done

echo "$MNT"
