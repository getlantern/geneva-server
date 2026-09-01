# Shared helpers for the docker-compose harnesses (e2e/run.sh, bench/run.sh).
# Source after setting COMPOSE to the compose invocation array; sourcing
# installs the KEEP-aware teardown trap.

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

harness_cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    "${COMPOSE[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap harness_cleanup EXIT

# wait_healthy <container> polls the sidecar control surface from inside the
# given container for up to 30 seconds. Returns non-zero if it never comes up,
# so the caller decides how loudly to fail.
wait_healthy() {
  local via="$1"
  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T "$via" curl -fsS http://server:8092/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}
