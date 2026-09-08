#!/usr/bin/env bash
# Real process test; all data and keys live in a disposable directory.
set -euo pipefail
binary=${1:?usage: bash scripts/e2e.sh /absolute/path/to/backuply}
work=$(mktemp -d /tmp/backuply-e2e.XXXXXX)
source_pid=
replica_pid=
cleanup() {
  if [[ -n "$replica_pid" ]]; then kill "$replica_pid" 2>/dev/null || true; wait "$replica_pid" 2>/dev/null || true; fi
  if [[ -n "$source_pid" ]]; then kill "$source_pid" 2>/dev/null || true; wait "$source_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
fail() { cat "$work"/*.log >&2; printf '%s\n' "$*" >&2; exit 1; }
source_id=$("$binary" init -state-dir "$work/source-state")
replica_id=$("$binary" init -state-dir "$work/replica-state")
cat > "$work/source.conf" <<EOF
[service]
listen = 127.0.0.1:0
state_dir = $work/source-state
scan_interval = 100ms
[peer "replica"]
address = 127.0.0.1:24800
device_id = $replica_id
[folder "projects"]
path = $work/source-data
source = local
peers = replica
EOF
"$binary" init -config "$work/source.conf" >/dev/null
mkdir -p "$work/source-data/nested"
dd if=/dev/zero of="$work/source-data/nested/file.bin" bs=262144 count=4 status=none
touch "$work/source-data/empty"
"$binary" run -config "$work/source.conf" >"$work/source.log" 2>&1 &
source_pid=$!
address=
for _ in {1..100}; do
  if status=$("$binary" status -config "$work/source.conf" 2>/dev/null); then
    address=$(printf '%s\n' "$status" | sed -n 's/.*"listen": "\([^"]*\)".*/\1/p')
    break
  fi
  sleep 0.1
done
[[ -n "$address" ]] || fail "source failed to start"
cat > "$work/replica.conf" <<EOF
[service]
listen = 127.0.0.1:0
state_dir = $work/replica-state
scan_interval = 100ms
[peer "source"]
address = $address
device_id = $source_id
[folder "projects"]
path = $work/replica-data
source = source
peers = source
EOF
"$binary" init -config "$work/replica.conf" >/dev/null
start_replica() {
  "$binary" run -config "$work/replica.conf" >>"$work/replica.log" 2>&1 &
  replica_pid=$!
}
wait_for_sync() {
  for _ in {1..150}; do
    if cmp -s "$work/source-data/nested/file.bin" "$work/replica-data/nested/file.bin" && [[ -f "$work/replica-data/empty" ]]; then return; fi
    sleep 0.1
  done
  fail "replicas did not converge"
}
start_replica
wait_for_sync
# Change exactly one fixed block, while the receiver is offline.
kill "$replica_pid"
wait "$replica_pid"
replica_pid=
printf X | dd of="$work/source-data/nested/file.bin" bs=1 seek=300000 conv=notrunc status=none
start_replica
wait_for_sync
"$binary" status -config "$work/replica.conf"
kill "$replica_pid"
wait "$replica_pid"
replica_pid=
[[ $("$binary" id -state-dir "$work/replica-state") == "$replica_id" ]] || fail "identity changed after restart"
printf '%s\n' "Two-process TLS sync, offline update, restart, and identity persistence: OK"
