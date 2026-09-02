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
      ct generation → OUT_Q (bypass)            SYN assigns ct generation
                  │                              ct generation → IN_Q (bypass)
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
                  via dedicated-UID raw socket
```

- **Connection generations.** An original inbound SYN is assigned the active
  immutable engine generation in kernel conntrack state. Every queue rule
  requires that mark, and NFQUEUE conntrack metadata supplies it to both
  directions without changing the packet's routing mark, so a connection cannot
  switch strategy halfway through. Unmarked flows which predate activation
  never match even when a new strategy widens its scope.
- **Two queues, one per direction.** The nftables rules send egress to the
  out-queue and ingress to the in-queue, so each callback knows its direction
  unambiguously — no per-packet inference.
- **Outbound** packets can fan out (`duplicate`/`fragment`) or change size
  (`tamper`), which an in-queue verdict cannot express, so a matched outbound
  packet is **dropped and its replacements reinjected** through a raw socket. The
  socket retains the packet's exact routing `SO_MARK`; an nftables `meta skuid`
  exclusion for the dedicated sidecar UID breaks the reinjection loop without
  changing the initial policy-route lookup.
- **Inbound** is single-in/single-out (branching is rejected at parse time), so
  it is handled with the in-queue verdict alone: accept, drop, or
  overwrite-and-accept.
- **Checksums / sequence fields** are recomputed by the library (its centralized
  checksum helpers), which also preserves fields a strategy *intentionally*
  corrupts. The runtime reinjects those bytes verbatim and never clobbers them.
- **Fail-open.** The queue rules use `bypass` when no listener is bound, and
  queue startup requires a kernel-acknowledged `NFQA_CFG_F_FAIL_OPEN` setting
  so a bound but full queue accepts new arrivals. Userspace ENOBUFS events are
  reported as unknown outcomes, never mislabeled as accepted.
- **No stale rules.** All rules live in one dedicated table that is created on
  start and deleted on stop; deleting the table removes everything atomically.

## Modes

- **prod** — the assigned strategy on a fleet box.
- **eval** — a candidate on a dedicated test box, plus a per-market **canary**
  that captures real header field values (window, TTL, MSS, options, flags, …)
  so the brain can mutate against values that actually occur. Seeded with a small
  static cold-start corpus.

The only difference is the canary (eval-only). Both modes support the versioned
adapter lifecycle below. A strategy update is prepared as a new immutable
generation and activated only for new TCP connections; existing connections
remain on their original generation through rollback and drain. The raw-DNA
`PUT /strategy` surface is disabled unless `--legacy-strategy-api` is selected,
which is mutually exclusive with authoritative v1 operation.

## Usage

```console
# Validate a strategy (no privileges; used by the GA pre-screen and CI):
geneva-server validate '[TCP:flags:S]-tamper{TCP:flags:replace:SA}-| \/'

# Run in prod mode. It starts inactive; the v1 adapter activates desired state:
sudo geneva-server run \
  --mode=prod \
  --port=443 --iface=eth0 \
  --control-addr=127.0.0.1:8092
```

Requires `CAP_NET_ADMIN` + `CAP_NET_RAW`, `nft`, and `ethtool`. Production
requires `--iface` so controller-owned offload changes remain restorable.
See [`deploy/`](deploy/) for the systemd unit and provisioning notes, and
`--help` for the full flag set.

## Control / health surface

The control surface carries only what has to be synchronous against one named
box. Everything else is exported as metrics (below).

| Method + path   | Mode      | Purpose                                                     |
| --------------- | --------- | ----------------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, engine/verdict/inbound-TCP stats            |
| `GET /strategy` | legacy opt-in | current raw strategy DNA                                 |
| `PUT /strategy` | legacy opt-in | compatibility prepare + activate for new connections     |
| `GET /canary`   | eval only | per-market captured field-value pool                        |
| `GET /v1/adapter/descriptor` | both | numeric protocol/schema versions and bounded capabilities |
| `POST /v1/adapter/verify` | both | validate an artifact and immutable identity without mutation |
| `POST /v1/adapter/prepare` | both | persist an identity-bound deployment (256 KiB decoded artifact limit) |
| `POST /v1/adapter/activate-for-new-connections` | both | assign future SYNs to a prepared artifact after union staging |
| `POST /v1/adapter/deactivate-for-new-connections` | both | identity-fenced stop of new-SYN assignment |
| `GET /v1/adapter/status` | both | generic active/prepared/draining identities and bounded drain counts |
| `POST /v1/adapter/drain` | both | bounded conntrack count for an artifact identity |
| `POST /v1/adapter/garbage-collect` | both | identity keep-set GC of zero-flow generations |
| `POST /v1/adapter/rollback` | both | restage/reactivate a complete previous-known-good artifact |

All control operations are unauthenticated, so keep `--control-addr` on a
private interface (see [`deploy/`](deploy/)).

The exact numeric v1 wire schema, identity preconditions, and retry semantics
are in [`docs/adapter-v1.md`](docs/adapter-v1.md).

### Generation and mark invariants

Geneva formally reserves conntrack bits `0xfffff000` as `0x67GGGxxx`, where
`GGG` is generation 1..4095 and the low 12 bits are preserved. The repository
audit found Lantern's `0x438`/1088 TPROXY marks and phost policy-routing marks
(745 and following) are packet marks today, with no `CONNMARK` save/restore;
coexistence is nevertheless intentional. SYN assignment preserves every bit
outside Geneva's mask. NFQUEUE supplies the
generation directly as conntrack metadata, so dispatch never mutates the skb
mark and downstream exact `fwmark 0x438`/`0x440` rules still match. Raw
reinjection uses NFQUEUE's original packet mark exactly. The legacy `--mark`
flag is accepted but ignored. A foreign connmark with nonzero
reserved bits is never overwritten or steered. IDs are not reused while
present; reuse is allowed only after authoritative zero-flow GC.

`--no-nft` is rejected: without a transactional external programmer and exact
readback interface, the dynamic lifecycle cannot truthfully report successful
activation, deactivation, rollback, or cleanup.

Activation uses two complete nft transactions. The first verifies and installs
the union of old and candidate generation scopes while SYN assignment still
names the old generation. The second changes only the new-SYN assignment. Thus
no packet can be assigned before its immutable engine and rules are live. The
state needed to reconstruct every live engine is atomically persisted and
file/directory-synced at `--adapter-state-file` before either transaction. Every
restart which sees active intent first reinstalls the neutral boundary and
sweeps unowned conntracks before restoring assignment, then flips directly from
neutral+full-union to active+full-union without an unassigned gap. Unknown orphaned
namespace marks disable new assignment and fail open rather than being applied
to the wrong DNA. First activation temporarily neutral-marks both existing
relevant conntracks and SYNs arriving during the sweep before flipping
assignment, so a pre-activation half-open SYN retransmission cannot cross the
boundary.

State v2 retains the artifact's exact protocol, schema, and required runtime
metadata and revalidates it against the installed descriptor before restart
activation. Corrupt, incompatible, or metadata-less v1 state is durably
quarantined; the sidecar stays inactive/unsafe and reports unhealthy while the
loopback lifecycle remains available. A newer t8 desired snapshot remediates via
the ordinary `Prepare` → `Verify` → `ActivateForNewConnections` sequence after
Geneva freshly verifies neutral kernel state and snapshots conntrack. The proof
is never persisted; Prepare can repeat it in the same process after a transient
startup proof failure or completed integrity reconciliation. Prepare and Verify
keep health unsafe, and only successful safe activation clears it. Orphan
generation IDs remain reserved and never enter union rules. An absent-artifact
rollback likewise allocates only an ID proven zero-flow by a fresh authoritative
snapshot. Production authoritative mode requires a nonempty
`--adapter-state-file`.

The lifecycle status exposes only the canonical artifact digest: bare lowercase
64-character SHA-256 hex. Raw DNA remains confined to the legacy,
loopback-private `GET /strategy` and `/healthz` compatibility responses and the
mode-0600 reconstruction file; it is never added to lifecycle status, logs, or
telemetry. The default
live-generation budget is three (`--max-generations`); preparation refuses a
fourth until one is drained and collected. The independently configurable
`--max-scoped-generations` (default three) and
`--max-every-packet-generations` (default two) admission budgets reflect their
very different packet-processing costs; the operator-only steering snapshot in
`/healthz` reports each private generation's `resource_class`.

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
`fin`, `ack_only`, `data`, plus `fragment` for non-initial IPv4 fragments and
`undecodable` for headers that could not be read), so the `syn`-versus-`data`
ratio per market is a usable estimate of the box's IP having been burned — and clean test-box IP
supply is the binding cost of GA exploration, so that estimate is what an
adaptive exploration posture budgets against. Injected resets show up as `rst`.

Every inbound packet increments exactly one bucket — fragments and unreadable
headers included — so the counts sum to everything observed and a ratio between
two of them means what it appears to mean. `fragment` is worth watching in its
own right: inbound fragmentation is a censor evasion and a middlebox behaviour,
not something a normal proxy flow produces. A nonzero `undecodable` means the
steering rules are delivering something other than IPv4/TCP, not that a censor
did anything.

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

Run the root/network-namespace release gate explicitly before staging:

```console
sudo GENEVA_KERNEL_INTEGRATION=1 go test ./e2e -run TestKernelGenerationLifecycle -v
```

The [`e2e/`](e2e/) suite stands up a proxy + sidecar + client over real Docker
networking and asserts the acceptance criteria: normal service survives a valid
strategy, only the intended port is steered, and no nftables rules leak on
shutdown.
