#!/usr/bin/env bash
# End-to-end test of the geneva-server sidecar over real Docker networking.
#
# Proves the acceptance criteria from getlantern/engineering#3859:
#   1. Normal service survives a valid strategy (byte-for-byte payload integrity
#      through a duplicate strategy that drops-and-reinjects every data packet).
#   2. Only the intended proxy TCP traffic enters the queue (steering is scoped
#      to port 8080; an unrelated :9090 service is untouched and still serves).
#   3. Runtime-owned nftables rules do not leak: after the sidecar stops, its
#      dedicated table is gone and the service still serves.
#
# Usage: e2e/run.sh   (set KEEP=1 to leave containers running for inspection)
set -euo pipefail

cd "$(dirname "$0")"
COMPOSE=(docker compose -f docker-compose.yml)

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    "${COMPOSE[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

step "Build and start server + sidecar"
"${COMPOSE[@]}" up -d --build server sidecar
"${COMPOSE[@]}" --profile tools up -d --build tester

# Wait for the control surface (proves the sidecar came up and installed rules).
step "Wait for the control/health surface"
for i in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz >/dev/null 2>&1; then
    break
  fi
  [[ $i -eq 30 ]] && fail "control surface never became healthy"
  sleep 1
done
mode=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq -r .mode)
[[ "$mode" == "prod" ]] && pass "control surface healthy (mode=$mode)" || fail "unexpected mode: $mode"

step "1. Normal service survives the strategy (payload integrity)"
"${COMPOSE[@]}" exec -T tester sh -c '
  /usr/local/bin/echo -emit -size 1048576 > /tmp/want &&
  curl -fsS http://server:8080/ -o /tmp/got &&
  cmp /tmp/want /tmp/got' \
  && pass "1 MiB payload received byte-for-byte through the duplicate strategy" \
  || fail "payload mismatch: the strategy corrupted normal service"

step "Manipulation actually happened (health snapshot)"
health=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz)
echo "$health" | jq '{packets_in: .engine.packets_in, expanded: .engine.expanded, reinjected: .verdicts.reinjected, inject_fails: .verdicts.inject_fails}'
pin=$(echo "$health" | jq '.engine.packets_in')
exp=$(echo "$health" | jq '.engine.expanded')
rei=$(echo "$health" | jq '.verdicts.reinjected')
fails=$(echo "$health" | jq '.verdicts.inject_fails')
[[ "$pin" -gt 0 ]]  && pass "packets entered the queue ($pin)"        || fail "no packets entered the queue"
[[ "$exp" -gt 0 ]]  && pass "data packets were duplicated ($exp)"     || fail "strategy never fired"
[[ "$rei" -gt 0 ]]  && pass "packets were reinjected ($rei)"          || fail "no reinjection occurred"
[[ "$fails" -eq 0 ]] && pass "zero reinjection failures"              || fail "$fails reinjection failures"

# The strategy under test is outbound-only, and nothing inbound is steered for
# it: no --observe-inbound, no inbound tree. The counts come from nftables
# counters that classify what arrives in the kernel, which is the only reason
# this signal survives steering being scoped to the strategy.
step "Inbound TCP classification from kernel counters (the censor-reachability signal)"
health=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz)
echo "$health" | jq '.inbound_tcp'
syn=$(echo "$health" | jq '.inbound_tcp.events.syn')
data=$(echo "$health" | jq '.inbound_tcp.events.data')
# The tester completed a real 1 MiB transfer, so the uncensored baseline is syns
# followed by data. A burned box is the same shape with data at zero.
[[ "$syn"  -gt 0 ]] && pass "inbound SYNs counted in the kernel ($syn)"          || fail "no inbound SYNs counted"
[[ "$data" -gt 0 ]] && pass "inbound data segments counted in the kernel ($data)" || fail "no inbound data counted"
# And the point of doing it in the kernel: none of those packets was queued.
inpkts=$("${COMPOSE[@]}" exec -T sidecar nft list table inet geneva_server | grep -cE "tcp dport 8080 .*queue" || true)
[[ "$inpkts" -eq 0 ]] && pass "no inbound queue rule: the signal cost no userspace round trip" \
  || fail "inbound packets are being queued after all"

step "2. Steering is scoped to the proxy port and to what the strategy can match"
ruleset=$("${COMPOSE[@]}" exec -T sidecar nft list table inet geneva_server)
echo "$ruleset"
echo "$ruleset" | grep -q "tcp sport 8080" && pass "egress steering scoped to sport 8080" || fail "missing egress rule"
echo "$ruleset" | grep -q "9090" && fail "ruleset unexpectedly references port 9090" || pass "unrelated port 9090 not steered"
# The strategy is outbound-only, so nothing inbound may be queued — the counters
# handle inbound without taking a packet out of the kernel.
echo "$ruleset" | grep -qE "tcp dport 8080 .*queue" && fail "inbound queue rule installed for an outbound-only strategy" \
  || pass "no inbound steering for an outbound-only strategy"
echo "$ruleset" | grep -q "jump censor_in" && pass "inbound classified by the counter chain instead" \
  || fail "missing the censor classification jump"
# And the egress rule must carry the flag match, or bulk data is still being
# queued for a strategy that only fires on PSH|ACK.
echo "$ruleset" | grep -q "tcp flags" && pass "egress steering narrowed to the strategy's flags" \
  || fail "egress rule not narrowed to the strategy's trigger flags"
"${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS http://server:9090/healthz' >/dev/null \
  && pass "unrelated :9090 service still serves normally" \
  || fail ":9090 service broke"

step "In-place strategy reload on the running prod sidecar"
newdna='[TCP:flags:S]-tamper{TCP:flags:replace:SA}-| \/'
"${COMPOSE[@]}" exec -T tester sh -c "curl -fsS -X PUT --data-binary '$newdna' http://server:8092/strategy" >/dev/null \
  && pass "PUT /strategy accepted on a prod-mode box" \
  || fail "PUT /strategy rejected"
got=$("${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS http://server:8092/strategy' | jq -r .strategy)
[[ "$got" == "$newdna" ]] && pass "strategy swapped in place (no restart)" || fail "strategy not updated: $got"
"${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS http://server:8080/healthz' >/dev/null \
  && pass "service still serves after the in-place swap" \
  || fail "service broke after strategy swap"

step "3. An empty strategy takes the box off the data path entirely"
"${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS -X PUT --data-binary "" http://server:8092/strategy' >/dev/null \
  && pass "PUT of an empty strategy accepted" \
  || fail "PUT of an empty strategy rejected"
if "${COMPOSE[@]}" exec -T sidecar nft list table inet geneva_server >/dev/null 2>&1; then
  fail "steering table still present with a strategy that can match nothing"
else
  pass "steering table removed: no packet takes the round trip"
fi
steering=$("${COMPOSE[@]}" exec -T tester curl -fsS http://server:8092/healthz | jq -r .steering.steering)
[[ "$steering" == "false" ]] && pass "health surface reports steering=false" || fail "health surface reports steering=$steering"
"${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS http://server:8080/healthz' >/dev/null \
  && pass "service still serves with the sidecar idle" \
  || fail "service broke after the strategy was withdrawn"
# Put a strategy back, so the teardown check below exercises a live table.
"${COMPOSE[@]}" exec -T tester sh -c "curl -fsS -X PUT --data-binary '$newdna' http://server:8092/strategy" >/dev/null

step "4. Clean teardown leaves no stale rules"
"${COMPOSE[@]}" stop -t 10 sidecar >/dev/null
"${COMPOSE[@]}" logs sidecar 2>&1 | grep -q "nftables steering removed" \
  && pass "sidecar logged rule teardown on shutdown" \
  || fail "sidecar did not log teardown"
# Inspect the netns from a fresh container: the table must be gone.
if "${COMPOSE[@]}" run --rm --entrypoint nft probe list table inet geneva_server >/dev/null 2>&1; then
  fail "geneva_server table still present after shutdown: rules leaked"
else
  pass "geneva_server table absent after shutdown"
fi
"${COMPOSE[@]}" exec -T tester sh -c 'curl -fsS http://server:8080/healthz' >/dev/null \
  && pass "proxy still serves after the sidecar is gone (fail-open)" \
  || fail "proxy broke after sidecar shutdown"

printf '\n\033[1;32mALL E2E CHECKS PASSED\033[0m\n'
