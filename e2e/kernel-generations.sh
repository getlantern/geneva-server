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
failure_diagnostics() {
  local rc=$?
  echo "kernel-gate: FAILED line $1: $2 (exit $rc)" >&2
  "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz >&2 || true
  "${COMPOSE[@]}" exec -T probe nft list table inet geneva_server >&2 || true
  "${COMPOSE[@]}" logs --tail=100 sidecar >&2 || true
  return "$rc"
}
trap 'failure_diagnostics "$LINENO" "$BASH_COMMAND"' ERR
trap cleanup EXIT

api() {
  local path=$1 body=$2
  printf '%s' "$body" | "${COMPOSE[@]}" exec -T tester \
    curl -fsS -H 'Content-Type: application/json' --data-binary @- "http://server:8092${path}"
}

status() {
  "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/v1/adapter/status
}

artifact() {
  local revision=$1 dna=$2 digest size payload
  digest=$(printf '%s' "$dna" | sha256sum | awk '{print $1}')
  size=$(printf '%s' "$dna" | wc -c | tr -d ' ')
  payload=$(printf '%s' "$dna" | base64 -w0)
  jq -cn \
    --arg revision "$revision" --arg digest "$digest" --argjson size "$size" \
    --arg runtime "$runtime_version" --arg payload "$payload" \
    '{metadata:{technique:"geneva",revision:$revision,content_sha256:$digest,size:$size,adapter_protocol:1,required_runtime_name:"geneva-engine",required_runtime_version:$runtime,schema_version:1},payload:$payload}'
}

identity() {
  jq -c '{technique:.metadata.technique,revision:.metadata.revision,digest:.metadata.content_sha256}' <<<"$1"
}

prepare() {
  api /v1/adapter/prepare "$1" >/dev/null
  api /v1/adapter/verify "$1" >/dev/null
}

activate() {
  api /v1/adapter/activate-for-new-connections "$1" >/dev/null
}

generation_count() {
  local generation=$1 mark decimal
  mark=$((0x67000000 + (generation << 12)))
  printf -v decimal '%u' "$mark"
  "${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | \
    grep -Ec "mark=(${decimal}|0x$(printf '%08x' "$mark"))" || true
}

wait_count() {
  local generation=$1 comparison=$2 deadline=$((SECONDS + 15)) value=0
  while (( SECONDS < deadline )); do
    value=$(generation_count "$generation")
    if [[ "$comparison" == positive && "$value" -gt 0 ]] || [[ "$comparison" == zero && "$value" -eq 0 ]]; then
      printf '%s' "$value"
      return 0
    fi
    sleep 0.2
  done
  echo "generation $generation count did not become $comparison (last=$value)" >&2
  return 1
}

mark_observer_packets() {
  local mark=$1
  "${COMPOSE[@]}" exec -T probe nft list chain inet geneva_mark_probe observe | \
    awk -v mark="$mark" '$0 ~ "meta mark " mark { for (i = 1; i <= NF; i++) if ($i == "packets") { print $(i + 1); exit } }'
}

echo 'kernel-gate: clean prior state, build, and start inactive'
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build server sidecar
"${COMPOSE[@]}" --profile tools up -d --build tester probe
for _ in $(seq 1 60); do
  if descriptor=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/v1/adapter/descriptor 2>/dev/null); then
    break
  fi
  sleep 0.5
done
runtime_version=$(jq -r .runtime_version <<<"$descriptor")
[[ -n "$runtime_version" ]]
[[ "$(status | jq '.active == null')" == true ]]

echo 'kernel-gate: open established and half-open flows before activation'
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/preactivation.pid; exec curl --local-port 39000 -fsS --no-buffer "http://server:8080/hold?duration=55s" >/tmp/preactivation.out'
sleep 1

tester_ip=$("${COMPOSE[@]}" exec -T probe getent ahostsv4 tester | awk 'NR==1 {print $1}')
"${COMPOSE[@]}" exec -T probe sh -c "nft add table inet geneva_halfopen; nft 'add chain inet geneva_halfopen output { type filter hook output priority -200; policy accept; }'; nft add rule inet geneva_halfopen output ip daddr $tester_ip tcp sport 8080 tcp dport 39001 tcp flags \& '(syn|ack)' == '(syn|ack)' drop"
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/halfopen.pid; exec curl --local-port 39001 -fsS --no-buffer "http://server:8080/hold?duration=50s" >/tmp/halfopen.out'
sleep 1
halfopen_before=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | grep 'sport=39001')
printf '%s\n' "$halfopen_before" | grep -q 'SYN_SENT'
printf '%s\n' "$halfopen_before" | grep -q '\[UNREPLIED\]'

# Generation 1 has an unexpressible payload scope, so it queues every inbound
# packet, plus an unchanged outbound ACK path. That widens across the pre-existing
# flow, proves inbound modification, and exercises unchanged outbound verdicts.
dna1='[TCP:flags:A*]-send-| \/ [TCP:flags:S]-tamper{IP:ttl:replace:62}-|[TCP:load:GENEVA_NEVER]-send-|'
dna2='[TCP:flags:A*]-duplicate-| \/ [TCP:flags:S]-tamper{IP:ttl:replace:62}-|[TCP:load:GENEVA_NEVER]-send-|'
one=$(artifact kernel-r1 "$dna1")
two=$(artifact kernel-r2 "$dna2")
identity_one=$(identity "$one")
identity_two=$(identity "$two")

prepare "$one"
# Simulate the exact crash point after durable active intent but before its
# neutral boundary. The stopped container's private state is edited to the
# post-persist phase; restart must neutralize the already-existing conntracks
# before it restores generation-1 assignment.
sidecar_id=$("${COMPOSE[@]}" ps -q sidecar)
crash_state=$(mktemp)
docker cp "$sidecar_id:/tmp/kernel-adapter-state.json" "$crash_state"
jq '.active_new_generation=1 | .generations[0].phase="active"' "$crash_state" >"${crash_state}.new"
mv "${crash_state}.new" "$crash_state"
docker cp "$crash_state" "$sidecar_id:/tmp/kernel-adapter-state.json"
"${COMPOSE[@]}" exec -T sidecar chown 65534:65534 /tmp/kernel-adapter-state.json
"${COMPOSE[@]}" exec -T sidecar chmod 0600 /tmp/kernel-adapter-state.json
docker kill --signal KILL "$sidecar_id" >/dev/null
"${COMPOSE[@]}" start sidecar >/dev/null
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/v1/adapter/status >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
[[ "$(status | jq --argjson want "$identity_one" '.active == $want')" == true ]]
halfopen_after_flip=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | grep 'sport=39001')
printf '%s\n' "$halfopen_after_flip" | grep -q 'SYN_SENT'
printf '%s\n' "$halfopen_after_flip" | grep -q '\[UNREPLIED\]'
printf '%s\n' "$halfopen_after_flip" | grep -Eq 'mark=(1728053248|0x67000000)'
"${COMPOSE[@]}" exec -T tester sh -c 'kill -0 "$(cat /tmp/halfopen.pid)"'
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
"${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null | \
  grep 'sport=39000' | grep -Eq 'mark=(1728053248|0x67000000)'
"${COMPOSE[@]}" exec -T tester sh -c 'kill -0 "$(cat /tmp/halfopen.pid)"'

flows=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null || true)
printf '%s\n' "$flows"
"${COMPOSE[@]}" exec -T tester sh -c 'kill -0 "$(cat /tmp/preactivation.pid)"'

echo 'kernel-gate: execute a real inbound strategy and hold generation 1'
tampered_before=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq '.engine.tampered')
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/generation1.pid; exec curl --local-port 39002 -fsS --no-buffer "http://server:8080/hold?duration=50s" >/tmp/generation1.out'
[[ "$(wait_count 1 positive)" -gt 0 ]]
for _ in $(seq 1 30); do
  tampered_after=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq '.engine.tampered')
  [[ "$tampered_after" -gt "$tampered_before" ]] && break
  sleep 0.2
done
[[ "$tampered_after" -gt "$tampered_before" ]]
"${COMPOSE[@]}" exec -T probe nft list table inet geneva_server | grep -qE 'tcp dport 8080 .*queue .*101'
flows=$("${COMPOSE[@]}" exec -T probe conntrack -L -p tcp --dport 8080 -o extended 2>/dev/null || true)
printf '%s\n' "$flows" | grep 'sport=39002' | grep -Eq 'mark=(1728057344|0x67001000)'

echo 'kernel-gate: install exact-fwmark policy routes and later-hook observer'
gateway=$("${COMPOSE[@]}" exec -T probe sh -c "ip route show default | awk 'NR==1 {print \$3}'")
"${COMPOSE[@]}" exec -T probe ip route add table 100 default via "$gateway" dev eth0
"${COMPOSE[@]}" exec -T probe ip route add table 101 default via "$gateway" dev eth0
"${COMPOSE[@]}" exec -T probe ip rule add priority 100 fwmark 0x438/0xffffffff lookup 100
"${COMPOSE[@]}" exec -T probe ip rule add priority 101 fwmark 0x440/0xffffffff lookup 101
"${COMPOSE[@]}" exec -T probe sh -c 'nft add table inet geneva_mark_probe; nft "add chain inet geneva_mark_probe observe { type route hook output priority -148; policy accept; }"; nft add rule inet geneva_mark_probe observe meta mark 0x438 counter; nft add rule inet geneva_mark_probe observe meta mark 0x440 counter'
"${COMPOSE[@]}" exec -T probe ip route get "$tester_ip" mark 0x438 | grep -q 'table 100'
"${COMPOSE[@]}" exec -T probe ip route get "$tester_ip" mark 0x440 | grep -q 'table 101'

"${COMPOSE[@]}" exec -T tester curl -fsS 'http://server:8080/?mark=0x438' >/dev/null
"${COMPOSE[@]}" exec -T probe nft list chain inet geneva_mark_probe observe | \
  grep 'meta mark 0x00000438' | grep -Eq 'packets [1-9]'

echo 'kernel-gate: activate generation 2 while generation 1 remains open'
prepare "$two"
activate "$two"
[[ "$(status | jq --argjson want "$identity_two" '.active == $want')" == true ]]
"${COMPOSE[@]}" exec -d tester sh -c \
  'echo $$ >/tmp/generation2.pid; exec curl --local-port 39003 -fsS --no-buffer "http://server:8080/hold?duration=45s" >/tmp/generation2.out'
[[ "$(wait_count 1 positive)" -gt 0 ]]
[[ "$(wait_count 2 positive)" -gt 0 ]]

health_before=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz)
before=$(printf '%s' "$health_before" | jq '.engine.packets_in')
reinjected_before=$(printf '%s' "$health_before" | jq '.verdicts.reinjected')
mark_440_before=$(mark_observer_packets '0x00000440')
"${COMPOSE[@]}" exec -T tester curl -fsS 'http://server:8080/?mark=0x440' >/dev/null
health=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz)
after=$(printf '%s' "$health" | jq '.engine.packets_in')
reinjected_after=$(printf '%s' "$health" | jq '.verdicts.reinjected')
mark_440_after=$(mark_observer_packets '0x00000440')
[[ "$reinjected_after" -gt "$reinjected_before" ]]
[[ "$((after - before))" -lt 10000 ]]
[[ "$mark_440_after" -gt "$mark_440_before" ]]

echo 'kernel-gate: rollback keeps both flows, then bounded drain and keep-set GC'
api /v1/adapter/rollback "$one" >/dev/null
[[ "$(status | jq --argjson want "$identity_one" '.active == $want')" == true ]]
[[ "$(wait_count 1 positive)" -gt 0 ]]
[[ "$(wait_count 2 positive)" -gt 0 ]]
drain=$(api /v1/adapter/drain "$identity_two")
[[ "$(printf '%s' "$drain" | jq '.remaining_connections')" -gt 0 ]]
"${COMPOSE[@]}" exec -T tester sh -c 'kill "$(cat /tmp/generation2.pid)"; wait "$(cat /tmp/generation2.pid)" 2>/dev/null || true'
"${COMPOSE[@]}" exec -T probe conntrack -D --mark 0x67002000/0xfffff000 >/dev/null
[[ "$(wait_count 2 zero)" -eq 0 ]]
drain=$(api /v1/adapter/drain "$identity_two")
[[ "$(printf '%s' "$drain" | jq '.complete')" == true ]]
api /v1/adapter/garbage-collect "$(jq -cn --argjson one "$identity_one" '{keep:[$one]}')" >/dev/null
[[ "$(status | jq --argjson gone "$identity_two" '[.prepared[] | select(. == $gone)] | length')" -eq 0 ]]
[[ "$(wait_count 1 positive)" -gt 0 ]]

echo 'kernel-gate: a verified second process cannot acquire live queues'
collision_packets_before=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq '.engine.packets_in')
collision_log=$(mktemp)
if "${COMPOSE[@]}" exec -T sidecar /usr/local/bin/geneva-server run \
    --mode=prod --port=8080 --iface=eth0 --control-addr=127.0.0.1:8093 \
    --adapter-state-file=/tmp/collision-state.json --reinject-bypass-uid=65534 \
    >"$collision_log" 2>&1; then
  echo 'second sidecar unexpectedly acquired NFQUEUE ownership' >&2
  exit 1
fi
grep -q 'engine registry ready' "$collision_log"
grep -Eq 'open (out|in)-queue (100|101): .*bind queue' "$collision_log"
"${COMPOSE[@]}" exec -T tester curl -fsS http://server:8080/healthz >/dev/null
for _ in $(seq 1 30); do
  collision_packets_after=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq '.engine.packets_in')
  [[ "$collision_packets_after" -gt "$collision_packets_before" ]] && break
  sleep 0.2
done
[[ "$collision_packets_after" -gt "$collision_packets_before" ]]

echo 'kernel-gate: bound queue overload is fail-open at max length 1'
"${COMPOSE[@]}" pause sidecar >/dev/null
successes=$("${COMPOSE[@]}" exec -T tester sh -c '
  n=0; pids=""
  for i in 1 2 3 4 5 6 7 8; do
    (curl -fsS --max-time 5 http://server:8080/healthz >/dev/null) & pids="$pids $!"
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
