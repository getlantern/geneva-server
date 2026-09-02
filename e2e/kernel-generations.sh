#!/usr/bin/env bash
# Root-gated kernel release test for connection generations, exact mark
# restoration/reinjection routing, queue ownership and overload fail-open.
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.kernel.yml)

cleanup() {
  "${COMPOSE[@]}" unpause sidecar >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

api() {
  local path=$1 body=$2
  printf '%s' "$body" | "${COMPOSE[@]}" exec -T tester \
    curl -fsS -H 'Content-Type: application/json' --data-binary @- "http://server:8092${path}"
}

status() {
  "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/v1/adapter/status
}

deployment() {
  local generation=$1 revision=$2 digest=$3
  jq -cn --argjson generation "$generation" --arg revision "$revision" --arg digest "$digest" \
    '{generation:$generation,identity:{technique:"geneva",revision:$revision,digest:$digest}}'
}

prepare() {
  local dep=$1 dna=$2
  api /v1/adapter/prepare "$(jq -cn --argjson deployment "$dep" --arg artifact "$dna" \
    '{schema_version:1,deployment:$deployment,artifact:$artifact}')" >/dev/null
}

activate() {
  local target=$1 expected=$2
  api /v1/adapter/activate-new "$(jq -cn --argjson deployment "$target" --argjson expected_active "$expected" \
    '{deployment:$deployment,expected_active:$expected_active}')" >/dev/null
}

wait_count() {
  local generation=$1 comparison=$2 deadline=$((SECONDS + 15)) value
  while (( SECONDS < deadline )); do
    value=$(status | jq --argjson generation "$generation" \
      '[.generations[] | select(.generation == $generation) | .connections][0] // 0')
    if [[ "$comparison" == positive && "$value" -gt 0 ]] || [[ "$comparison" == zero && "$value" -eq 0 ]]; then
      printf '%s' "$value"
      return 0
    fi
    sleep 0.2
  done
  echo "generation $generation count did not become $comparison (last=$value)" >&2
  return 1
}

echo 'kernel-gate: build and start inactive sidecar in the proxy network namespace'
"${COMPOSE[@]}" up -d --build server sidecar
"${COMPOSE[@]}" --profile tools up -d --build tester probe
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/v1/adapter/descriptor >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
[[ "$(status | jq '.active_new_generation // 0')" -eq 0 ]]

echo 'kernel-gate: open a flow before first activation'
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/preactivation.pid; exec curl -fsS --no-buffer "http://server:8080/hold?duration=55s" >/tmp/preactivation.out'
sleep 1

# Hold a second connection half-open across activation. The client keeps
# retransmitting its original SYN while the server namespace temporarily drops
# SYN-ACKs. Once the drop is removed, that retransmission must retain the
# neutral connmark installed at the activation boundary rather than acquire the
# newly active generation.
tester_ip=$("${COMPOSE[@]}" exec -T probe getent ahostsv4 tester | awk 'NR==1 {print $1}')
"${COMPOSE[@]}" exec -T probe sh -c "nft add table inet geneva_halfopen; nft 'add chain inet geneva_halfopen output { type filter hook output priority -200; policy accept; }'; nft add rule inet geneva_halfopen output ip daddr $tester_ip tcp sport 8080 tcp dport 39001 tcp flags \& '(syn|ack)' == '(syn|ack)' drop"
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/halfopen.pid; exec curl --local-port 39001 -fsS --no-buffer "http://server:8080/hold?duration=50s" >/tmp/halfopen.out'
sleep 1
"${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | grep -q 'sport=39001'

dna1='[TCP:flags:A*]-send-| \/'
dna2='[TCP:flags:A*]-duplicate-| \/'
digest1=$(printf '%s' "$dna1" | sha256sum | awk '{print $1}')
digest2=$(printf '%s' "$dna2" | sha256sum | awk '{print $1}')
one=$(deployment 1 kernel-r1 "$digest1")
two=$(deployment 2 kernel-r2 "$digest2")

prepare "$one" "$dna1"
activate "$one" '{}'
"${COMPOSE[@]}" exec -T probe nft delete table inet geneva_halfopen
for _ in $(seq 1 50); do
  if "${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | \
    grep 'sport=39001' | grep -Eq 'mark=(1728053248|0x67000000)'; then
    break
  fi
  sleep 0.2
done
"${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | \
  grep 'sport=39001' | grep -Eq 'mark=(1728053248|0x67000000)'
"${COMPOSE[@]}" exec -T tester sh -c 'kill -0 "$(cat /tmp/halfopen.pid)"'

# The preactivation connection must have been neutralized, not captured by the
# widened every-packet scope. No generation-1 connection exists yet.
[[ "$(wait_count 1 zero)" -eq 0 ]]
flows=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null || true)
printf '%s\n' "$flows"
if printf '%s\n' "$flows" | grep -Eq 'mark=(1728057344|0x67001000)'; then
  echo 'preactivation flow was captured by generation 1' >&2
  exit 1
fi
"${COMPOSE[@]}" exec -T tester sh -c 'kill -0 "$(cat /tmp/preactivation.pid)"'

echo 'kernel-gate: hold a generation-1 flow and inspect conntrack affinity'
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/generation1.pid; exec curl -fsS --no-buffer "http://server:8080/hold?duration=50s" >/tmp/generation1.out'
[[ "$(wait_count 1 positive)" -gt 0 ]]
flows=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null || true)
printf '%s\n' "$flows"
printf '%s\n' "$flows" | grep -Eq 'mark=(1728057344|0x67001000)' # generation 1, original+reply tuple

echo 'kernel-gate: install exact-fwmark policy routes and a later-hook observer'
gateway=$("${COMPOSE[@]}" exec -T probe sh -c "ip route show default | awk 'NR==1 {print \$3}'")
"${COMPOSE[@]}" exec -T probe ip route add table 100 default via "$gateway" dev eth0
"${COMPOSE[@]}" exec -T probe ip route add table 101 default via "$gateway" dev eth0
"${COMPOSE[@]}" exec -T probe ip rule add priority 100 fwmark 0x438/0xffffffff lookup 100
"${COMPOSE[@]}" exec -T probe ip rule add priority 101 fwmark 0x440/0xffffffff lookup 101
"${COMPOSE[@]}" exec -T probe sh -c 'nft add table inet geneva_mark_probe; nft "add chain inet geneva_mark_probe observe { type route hook output priority -148; policy accept; }"; nft add rule inet geneva_mark_probe observe meta mark 0x438 counter; nft add rule inet geneva_mark_probe observe meta mark 0x440 counter'
"${COMPOSE[@]}" exec -T probe ip route get "$tester_ip" mark 0x438 | grep -q 'table 100'
"${COMPOSE[@]}" exec -T probe ip route get "$tester_ip" mark 0x440 | grep -q 'table 101'

# Generation 1 is unchanged. Exact 0x438 must survive queue dispatch/verdict
# without mutation so the later exact-mask rule observes it.
"${COMPOSE[@]}" exec -T tester curl -fsS 'http://server:8080/?mark=0x438' >/dev/null
"${COMPOSE[@]}" exec -T probe nft list chain inet geneva_mark_probe observe | \
  grep 'meta mark 0x00000438' | grep -Eq 'packets [1-9]'

echo 'kernel-gate: activate generation 2 while generation 1 remains open'
prepare "$two" "$dna2"
activate "$two" "$one"
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/generation2.pid; exec curl -fsS --no-buffer "http://server:8080/hold?duration=45s" >/tmp/generation2.out'
[[ "$(wait_count 1 positive)" -gt 0 ]]
[[ "$(wait_count 2 positive)" -gt 0 ]]

# Generation 2 duplicates. The queued replacement and raw extra must preserve
# exact 0x440; reinjection must happen without re-entering the queue forever.
before=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq '.engine.packets_in')
"${COMPOSE[@]}" exec -T tester curl -fsS 'http://server:8080/?mark=0x440' >/dev/null
health=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz)
after=$(printf '%s' "$health" | jq '.engine.packets_in')
[[ "$(printf '%s' "$health" | jq '.verdicts.reinjected')" -gt 0 ]]
[[ "$((after - before))" -lt 10000 ]]
"${COMPOSE[@]}" exec -T probe nft list chain inet geneva_mark_probe observe | \
  grep 'meta mark 0x00000440' | grep -Eq 'packets [1-9]'

echo 'kernel-gate: rollback without resetting either retained flow, then drain/GC generation 2'
api /v1/adapter/rollback "$(jq -cn --argjson deployment "$one" --argjson expected_active "$two" \
  '{deployment:$deployment,expected_active:$expected_active}')" >/dev/null
[[ "$(wait_count 1 positive)" -gt 0 ]]
[[ "$(wait_count 2 positive)" -gt 0 ]]
drain=$(api /v1/adapter/drain "$(jq -cn --argjson deployment "$two" '{deployment:$deployment}')")
[[ "$(printf '%s' "$drain" | jq '.connections')" -gt 0 ]]
"${COMPOSE[@]}" exec -T tester sh -c 'kill "$(cat /tmp/generation2.pid)"; wait "$(cat /tmp/generation2.pid)" 2>/dev/null || true'
[[ "$(wait_count 2 zero)" -eq 0 ]]
gc=$(api /v1/adapter/gc "$(jq -cn --argjson one "$one" '{keep:[$one]}')")
[[ "$(printf '%s' "$gc" | jq '[.removed[].generation] | index(2)')" != null ]]
[[ "$(wait_count 1 positive)" -gt 0 ]]

echo 'kernel-gate: a second listener cannot own the live queues'
if "${COMPOSE[@]}" run --rm --no-deps sidecar >/tmp/geneva-queue-collision.log 2>&1; then
  echo 'second sidecar unexpectedly acquired NFQUEUE ownership' >&2
  exit 1
fi
"${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz >/dev/null

echo 'kernel-gate: bound queue overload is fail-open at max length 1'
"${COMPOSE[@]}" pause sidecar >/dev/null
successes=$("${COMPOSE[@]}" exec -T tester sh -c '
  n=0
  pids=""
  for i in 1 2 3 4 5 6 7 8; do
    (curl -fsS --max-time 5 http://server:8080/healthz >/dev/null) &
    pids="$pids $!"
  done
  for p in $pids; do if wait "$p"; then n=$((n+1)); fi; done
  echo "$n"')
[[ "$successes" -gt 0 ]]
"${COMPOSE[@]}" unpause sidecar >/dev/null

echo 'kernel-gate: teardown removes steering before releasing queue ownership'
"${COMPOSE[@]}" stop -t 15 sidecar >/dev/null
if "${COMPOSE[@]}" exec -T probe nft list table inet geneva_server >/dev/null 2>&1; then
  echo 'Geneva nftables table survived sidecar teardown' >&2
  exit 1
fi

echo 'kernel-gate: PASS'
