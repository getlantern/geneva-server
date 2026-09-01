#!/usr/bin/env bash
# Sidecar data-plane benchmark.
#
# Answers one question: what does steering cost per packet, and how much of that
# cost survives when the strategy cannot possibly match the traffic? It sweeps
# the sidecar's states (absent, pass-through, handshake-only, tamper-everything)
# in both modes and prints a table.
#
# The headline column is CPU-SEC/GB, not MB/s. A docker bridge has no link
# ceiling, so throughput here says more about the host than about the sidecar,
# while CPU per byte moved is the quantity that decides whether a 1-vCPU VPS can
# carry a strategy at line rate.
#
# Usage: bench/run.sh [GB per condition] [streams]
#        KEEP=1 bench/run.sh    # leave the stack up for inspection
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE=(docker compose -f docker-compose.yml)
GB="${1:-2}"
STREAMS="${2:-1}"
BYTES=$(( GB * (1 << 30) / STREAMS ))

HANDSHAKE='[TCP:flags:S]-duplicate-| \/'
TAMPER_ALL='[TCP:flags:PA]-duplicate-| \/'

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
results=()

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    "${COMPOSE[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# sidecar_cpu prints the sidecar's cumulative CPU seconds (utime+stime of PID 1,
# which is geneva-server itself), or 0 when the sidecar is not running.
sidecar_cpu() {
  local ticks hz
  ticks=$("${COMPOSE[@]}" exec -T sidecar awk '{print $14+$15}' /proc/1/stat 2>/dev/null || echo 0)
  hz=$(getconf CLK_TCK)
  awk -v t="${ticks:-0}" -v hz="$hz" 'BEGIN{printf "%.3f", t/hz}'
}

# packets_in prints the engine's cumulative packet count, or 0 with no sidecar.
packets_in() {
  "${COMPOSE[@]}" exec -T client sh -c \
    'curl -fsS http://server:8092/healthz 2>/dev/null | jq -r .engine.packets_in' 2>/dev/null || echo 0
}

# measure runs one condition and appends a table row: label, MB/s, sidecar CPU
# seconds per GB, and nanoseconds of sidecar CPU per steered packet.
measure() {
  local label="$1"
  local cpu0 cpu1 pkt0 pkt1 mbps cpu_s gb_moved
  cpu0=$(sidecar_cpu); pkt0=$(packets_in)
  mbps=$("${COMPOSE[@]}" exec -T client /usr/local/bin/bulk \
           -get http://server:8080 -bytes "$BYTES" -streams "$STREAMS" | tail -1)
  cpu1=$(sidecar_cpu); pkt1=$(packets_in)

  gb_moved=$(awk -v g="$GB" 'BEGIN{print g}')
  cpu_s=$(awk -v a="$cpu0" -v b="$cpu1" 'BEGIN{printf "%.3f", b-a}')
  local per_gb ns_pkt pkts
  per_gb=$(awk -v c="$cpu_s" -v g="$gb_moved" 'BEGIN{printf "%.3f", (g>0)?c/g:0}')
  pkts=$(( pkt1 - pkt0 ))
  ns_pkt=$(awk -v c="$cpu_s" -v p="$pkts" 'BEGIN{printf "%.0f", (p>0)?c*1e9/p:0}')
  printf '  %-26s %8s MB/s   cpu %6ss   %6s s/GB   %9s pkts   %5s ns/pkt\n' \
    "$label" "$mbps" "$cpu_s" "$per_gb" "$pkts" "$ns_pkt"
  results+=("$(printf '%-26s|%8s|%7s|%9s|%6s' "$label" "$mbps" "$per_gb" "$pkts" "$ns_pkt")")
}

# put installs a strategy over the control API on a running sidecar.
put() {
  "${COMPOSE[@]}" exec -T client sh -c \
    "curl -fsS -X PUT --data-binary '$1' http://server:8092/strategy >/dev/null"
}

wait_healthy() {
  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T client curl -fsS http://server:8092/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "sidecar control surface never came up" >&2
  "${COMPOSE[@]}" logs sidecar | tail -20 >&2
  exit 1
}

start_sidecar() {
  local mode="$1" dna="$2"
  printf '%s' "$dna" > strategy.dna
  GENEVA_MODE="$mode" "${COMPOSE[@]}" up -d --no-deps sidecar >/dev/null
  wait_healthy
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

step "Baseline: $GB GB over $STREAMS stream(s), sidecar absent"
measure "no-sidecar"

# eval boots with no strategy at all: the state a test box sits in until the GA
# brain assigns it a candidate. It is the case that must cost nothing.
step "mode=eval"
start_sidecar eval ""
measure "eval/no-strategy"
put "$HANDSHAKE"; measure "eval/handshake-only"
put "$TAMPER_ALL"; measure "eval/tamper-every-packet"
"${COMPOSE[@]}" stop -t 10 sidecar >/dev/null

# prod refuses to boot without a strategy, so it starts on the handshake one.
# The last row is the rollback path: PUT "" must take the box back off the data
# path rather than leaving it steering packets it no longer manipulates.
step "mode=prod"
start_sidecar prod "$HANDSHAKE"
measure "prod/handshake-only"
put "$TAMPER_ALL"; measure "prod/tamper-every-packet"
put ""; measure "prod/rolled-back-to-empty"
"${COMPOSE[@]}" stop -t 10 sidecar >/dev/null

step "Summary"
printf '%-26s|%8s|%7s|%9s|%6s\n' "CONDITION" "MB/s" "CPU s/GB" "PACKETS" "ns/pkt"
printf '%s\n' "${results[@]}"
