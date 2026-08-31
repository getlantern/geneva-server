# geneva-server

A privileged sidecar that applies [Geneva](https://censorship.ai) strategies to
a proxy's connections at the outer IPv4/TCP packet layer, via **NFQUEUE**. It
runs alongside the proxy, steers only that proxy's TCP traffic, and never touches
the encrypted payload.

It embeds [`getlantern/geneva`](https://github.com/getlantern/geneva) — the
strategy parser, evaluator, and mutation/crossover operators — and stays fully
decoupled from the genetic algorithm. Strategy evolution lives in a separate GA
brain; this sidecar only *applies* a strategy and reports health/overhead.

Scope is **IPv4/TCP only** (no UDP, no IPv6), matching the library.

## How it works

```text
        proxy egress (sport=PORT)                     proxy ingress (dport=PORT)
                  │                                              │
      nftables: queue → OUT_Q (bypass)          nftables: queue → IN_Q (bypass)
                  │                                              │
                  ▼                                              ▼
        ┌───────────────────┐                        ┌───────────────────┐
        │  outbound hook     │                        │  inbound hook      │
        │  strategy.Apply    │                        │  strategy.Apply    │
        │  (DirectionOut)    │                        │  (DirectionIn)     │
        └─────────┬──────────┘                        └─────────┬──────────┘
    unchanged → ACCEPT                         unchanged → ACCEPT
    otherwise → DROP original                  dropped   → DROP
                + reinject 0..N packets         tampered  → overwrite-and-ACCEPT
                  via raw socket (SO_MARK)
```

- **Two queues, one per direction.** The nftables rules send egress to the
  out-queue and ingress to the in-queue, so each callback knows its direction
  unambiguously — no per-packet inference.
- **Outbound** packets can fan out (`duplicate`/`fragment`) or change size
  (`tamper`), which an in-queue verdict cannot express, so a matched outbound
  packet is **dropped and its replacements reinjected** through a raw socket. The
  socket carries a firewall mark; an nftables rule accepts marked packets before
  the queue rule, breaking the reinjection loop.
- **Inbound** is single-in/single-out (branching is rejected at parse time), so
  it is handled with the in-queue verdict alone: accept, drop, or
  overwrite-and-accept.
- **Checksums / sequence fields** are recomputed by the library (its centralized
  checksum helpers), which also preserves fields a strategy *intentionally*
  corrupts. The runtime reinjects those bytes verbatim and never clobbers them.
- **Fail-open.** The queue rules use `bypass`: if the sidecar dies, the kernel
  accepts the proxy's packets instead of dropping them.
- **No stale rules.** All rules live in one dedicated table that is created on
  start and deleted on stop; deleting the table removes everything atomically.

## Modes

- **prod** — the assigned strategy on a fleet box.
- **eval** — a candidate on a dedicated test box, plus a per-market **canary**
  that captures real header field values (window, TTL, MSS, options, flags, …)
  so the brain can mutate against values that actually occur. Seeded with a small
  static cold-start corpus.

The only difference is the canary (eval-only). Both modes accept a strategy
update in place: `PUT /strategy` validates the DNA and swaps it atomically, so it
takes effect on the next packet with no restart (the swap touches only the
strategy — the queues, nftables rules, and reinjector are untouched). Restarting
also works and is how a strategy is delivered at boot via the config path.

## Usage

```console
# Validate a strategy (no privileges; used by the GA pre-screen and CI):
geneva-server validate '[TCP:flags:S]-tamper{TCP:flags:replace:SA}-| \/'

# Run in prod mode, steering the proxy on :443:
sudo geneva-server run \
  --mode=prod \
  --strategy-file=/etc/geneva-server/strategy.dna \
  --port=443 --iface=eth0 \
  --control-addr=127.0.0.1:8092
```

Requires `CAP_NET_ADMIN` + `CAP_NET_RAW`, `nft`, and (for `--iface`) `ethtool`.
See [`deploy/`](deploy/) for the systemd unit and provisioning notes, and
`--help` for the full flag set.

## Control / health surface

The control surface carries only what has to be synchronous against one named
box. Everything else is exported as metrics (below).

| Method + path   | Mode      | Purpose                                                     |
| --------------- | --------- | ----------------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, strategy, engine/verdict/inbound-TCP stats |
| `GET /strategy` | both      | current strategy DNA                                        |
| `PUT /strategy` | both      | assign/replace the strategy in place (validated)            |
| `GET /canary`   | eval only | per-market captured field-value pool                        |

`PUT /strategy` is unauthenticated, so keep `--control-addr` on a private
interface (see [`deploy/`](deploy/)).

## Metrics

The sidecar exports OTLP metrics to the box's local collector, which forwards to
the fleet's backend. It does not serve a scrape endpoint: the pipeline already
exists, and a control plane SSH-ing to each box to read a counter neither scales
with the pool nor aggregates across it. Export is opt-in via the standard
`OTEL_EXPORTER_OTLP_*` environment variables — with none set, the sidecar runs
with metrics disabled and builds no provider.

Every series is labelled `geneva.mode` and, when the box's market is known,
`geo.country.iso_code`. No label carries a strategy DNA or candidate id:
candidate identity lives in the brain's tables behind opaque tokens, and a
per-candidate label would leak it and make cardinality track population size.

| Metric                        | Attributes            | Meaning                                        |
| ----------------------------- | --------------------- | ---------------------------------------------- |
| `geneva.engine.packets_in/out`, `geneva.engine.bytes_in/out` | — | volume through the engine |
| `geneva.engine.outcomes`      | `geneva.outcome`      | unchanged / dropped / tampered / expanded      |
| `geneva.engine.packet_overhead`, `geneva.engine.byte_overhead` | — | fan-out and expansion ratios |
| `geneva.engine.errors`        | —                     | decode / apply failures (each one failed open) |
| `geneva.runtime.verdicts`     | `geneva.verdict`      | accepted / dropped / modified                  |
| `geneva.runtime.reinjections` | `geneva.reinjection`  | raw-socket reinjection ok / failed             |
| `geneva.strategy_swaps`       | —                     | in-place strategy replacements                 |
| `geneva.uptime`               | —                     | seconds since start                            |
| `geneva.censor.inbound_tcp`   | `geneva.tcp_event`    | inbound TCP by flags/payload — see below       |

### `geneva.censor.inbound_tcp` — the signal clients cannot send

Clients report what they observe: a session's success and throughput. A
connection the censor kills during the handshake produces **no report at all** —
the client sees a dial failure, indistinguishable from never having dialled,
from a routing fault, or from going offline. Silence is not evidence.

The box sees the censor's work directly. `geneva.censor.inbound_tcp` counts
inbound TCP packets on the steered port by `geneva.tcp_event` (`syn`, `rst`,
`fin`, `ack_only`, `data`), so the `syn`-versus-`data` ratio per market is a
usable estimate of the box's IP having been burned — and clean test-box IP
supply is the binding cost of GA exploration, so that estimate is what an
adaptive exploration posture budgets against. Injected resets show up as `rst`.

The classifier is deliberately stateless — no per-flow table. Tracking handshake
completion by 4-tuple would be a strictly better signal but means unbounded
per-packet state on a box whose job is to stay out of the proxy's way; the ratio
needs nothing but the current packet's header.

## Development

```console
make build       # static binary → bin/geneva-server
make test        # unit + packet-level tests (root-gated nftables test self-skips)
make test-race   # with the race detector
make e2e         # full docker-networking end-to-end (see e2e/)
make docker      # build the deployable image
```

The [`e2e/`](e2e/) suite stands up a proxy + sidecar + client over real Docker
networking and asserts the acceptance criteria: normal service survives a valid
strategy, only the intended port is steered, and no nftables rules leak on
shutdown.
