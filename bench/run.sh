#!/usr/bin/env bash
# Sidecar data-plane benchmark.
#
# Answers one question: what does steering cost per packet, and how much of that
# cost survives when the strategy cannot possibly match the traffic? It sweeps
# the sidecar's states (absent, pass-through, handshake-only, tamper-everything)
# in both modes and prints a table.
#
# The headline column is CPU-SEC/GiB, not MiB/s. A docker bridge has no link
# ceiling, so throughput here says more about the host than about the sidecar,
# while CPU per byte moved is the quantity that decides whether a 1-vCPU VPS can
# carry a strategy at line rate.
#
# Units are binary throughout — GiB and MiB/s — because that is what the byte
# counts actually are.
#
# Usage: bench/run.sh [GiB per condition] [streams]
#        KEEP=1 bench/run.sh    # leave the stack up for inspection
set -euo pipefail

cd "$(dirname "$0")"
# The compose mount needs the file to exist before the sidecar starts; it is
# rewritten per condition and deliberately not tracked.
: > strategy.dna
COMPOSE=(docker compose -f docker-compose.yml)
source ../scripts/harness-lib.sh
GIB="${1:-2}"
STREAMS="${2:-1}"
BYTES=$(( GIB * (1 << 30) / STREAMS ))

HANDSHAKE='[TCP:flags:S]-duplicate-| \/'
# One packet in, one packet out, on every data packet: the common manipulation,
# and the one the in-queue modified verdict is meant to make cheap.
TAMPER_ALL='[TCP:flags:PA]-tamper{TCP:window:replace:100}-| \/'
# Two packets out on every data packet: the worst case, since the extra packet
# has to reach the wire through the raw socket.
DUP_ALL='[TCP:flags:PA]-duplicate-| \/'

results=()

# SIDECAR_EXPECTED says whether a sidecar should be answering. While it is "1",
# telemetry that cannot be collected aborts the run instead of reading as zero:
# a stopped sidecar reporting 0 CPU and 0 packets looks exactly like the ideal
# result, and a stale container left by an interrupted run silently produced a
# wrong baseline row once already.
SIDECAR_EXPECTED=0

# sidecar_cpu prints the sidecar's cumulative CPU seconds (utime+stime of PID 1,
# which is geneva-server itself), or 0 when no sidecar is expected to be running.
sidecar_cpu() {
  local ticks hz
  if ! ticks=$("${COMPOSE[@]}" exec -T sidecar awk '{print $14+$15}' /proc/1/stat 2>/dev/null); then
    [[ "$SIDECAR_EXPECTED" == "1" ]] && { echo "cannot read sidecar CPU while a sidecar is expected" >&2; exit 1; }
    ticks=0
  fi
  hz=$(getconf CLK_TCK)
  awk -v t="${ticks:-0}" -v hz="$hz" 'BEGIN{printf "%.3f", t/hz}'
}

# packets_in prints the engine's cumulative packet count, or 0 when no sidecar
# is expected to be running.
packets_in() {
  local out
  if ! out=$("${COMPOSE[@]}" exec -T client sh -c \
        'curl -fsS http://server:8092/healthz | jq -r .engine.packets_in' 2>/dev/null); then
    [[ "$SIDECAR_EXPECTED" == "1" ]] && { echo "cannot read the sidecar health surface while a sidecar is expected" >&2; exit 1; }
    out=0
  fi
  echo "${out:-0}"
}

# measure runs one condition and appends a table row: label, MiB/s, sidecar CPU
# seconds per GiB, and nanoseconds of sidecar CPU per steered packet.
measure() {
  local label="$1"
  local cpu0 cpu1 pkt0 pkt1 mbps cpu_s
  cpu0=$(sidecar_cpu); pkt0=$(packets_in)
  mbps=$("${COMPOSE[@]}" exec -T client /usr/local/bin/bulk \
           -get http://server:8080 -bytes "$BYTES" -streams "$STREAMS" | tail -1)
  cpu1=$(sidecar_cpu); pkt1=$(packets_in)

  cpu_s=$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.3f", b-a}')
  local per_gb ns_pkt pkts
  per_gb=$(awk -v c="$cpu_s" -v g="$GIB" 'BEGIN{printf "%.3f", (g>0)?c/g:0}')
  pkts=$(( pkt1 - pkt0 ))
  ns_pkt=$(awk -v c="$cpu_s" -v p="$pkts" 'BEGIN{printf "%.0f", (p>0)?c*1e9/p:0}')
  printf '  %-26s %8s MiB/s  cpu %6ss   %6s s/GiB  %9s pkts   %5s ns/pkt\n' \
    "$label" "$mbps" "$cpu_s" "$per_gb" "$pkts" "$ns_pkt"
  results+=("$(printf '%-26s|%8s|%7s|%9s|%6s' "$label" "$mbps" "$per_gb" "$pkts" "$ns_pkt")")
}

# put installs a strategy over the control API on a running sidecar.
put() {
  "${COMPOSE[@]}" exec -T client sh -c \
    "curl -fsS -X PUT --data-binary '$1' http://server:8092/strategy >/dev/null"
}

start_sidecar() {
  local mode="$1" dna="$2"
  printf '%s' "$dna" > strategy.dna
  GENEVA_MODE="$mode" "${COMPOSE[@]}" up -d --no-deps sidecar >/dev/null
  if ! wait_healthy client; then
    echo "sidecar control surface never came up" >&2
    "${COMPOSE[@]}" logs sidecar | tail -20 >&2
    exit 1
  fi
  SIDECAR_EXPECTED=1
}

# stop_sidecar takes the sidecar down and stops expecting telemetry from it.
stop_sidecar() {
  SIDECAR_EXPECTED=0
  "${COMPOSE[@]}" stop -t 10 sidecar >/dev/null
}

# Start from a torn-down stack. An interrupted run can leave the server's
# network namespace de-offloaded (an older sidecar build never restored the NIC),
# and on a veth pair that alone costs several times the throughput — enough to
# make every row in the table wrong in the same direction.
"${COMPOSE[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true

step "Build images and start the bulk server (no sidecar yet)"
# The sidecar image is built here rather than on first use: start_sidecar brings
# it up per condition without --build, and a stale image would silently
# benchmark the previous commit.
"${COMPOSE[@]}" build server sidecar >/dev/null
"${COMPOSE[@]}" up -d server >/dev/null
"${COMPOSE[@]}" --profile tools up -d client >/dev/null

# Remove, not stop: a sidecar left behind by an interrupted run would still be
# steering, and the baseline row would silently measure the old build.
"${COMPOSE[@]}" rm -sf sidecar >/dev/null 2>&1 || true

step "Baseline: $GIB GiB over $STREAMS stream(s), sidecar absent"
measure "no-sidecar"

# eval boots with no strategy at all: the state a test box sits in until the GA
# brain assigns it a candidate. It is the case that must cost nothing.
step "mode=eval"
start_sidecar eval ""
measure "eval/no-strategy"
put "$HANDSHAKE"; measure "eval/handshake-only"
put "$TAMPER_ALL"; measure "eval/tamper-every-packet"
put "$DUP_ALL"; measure "eval/duplicate-every-packet"
stop_sidecar

# prod refuses to boot without a strategy, so it starts on the handshake one.
# The last row is the rollback path: PUT "" must take the box back off the data
# path rather than leaving it steering packets it no longer manipulates.
step "mode=prod"
start_sidecar prod "$HANDSHAKE"
measure "prod/handshake-only"
put "$TAMPER_ALL"; measure "prod/tamper-every-packet"
put "$DUP_ALL"; measure "prod/duplicate-every-packet"
put ""; measure "prod/rolled-back-to-empty"
stop_sidecar

step "Summary"
printf '%-26s|%8s|%7s|%9s|%6s\n' "CONDITION" "MiB/s" "CPU s/GiB" "PACKETS" "ns/pkt"
printf '%s\n' "${results[@]}"
