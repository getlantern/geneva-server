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

- **prod** — one fixed strategy on a fleet box. Reload by restart.
- **eval** — a replaceable candidate on a dedicated test box, plus a per-market
  **canary** that captures real header field values (window, TTL, MSS, options,
  flags, …) so the brain can mutate against values that actually occur. Seeded
  with a small static cold-start corpus.

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

| Method + path   | Mode      | Purpose                                            |
| --------------- | --------- | -------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, strategy, engine & verdict stats  |
| `GET /metrics`  | both      | overhead measurements for the GA pre-screen        |
| `GET /strategy` | both      | current strategy DNA                               |
| `PUT /strategy` | eval only | assign/replace a candidate (validated first)       |
| `GET /canary`   | eval only | per-market captured field-value pool               |

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
