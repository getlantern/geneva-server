# Deploying geneva-server

The sidecar follows the `lantern-box` / `datacap` / `httpproxy` deployment
pattern: a single static binary shipped in a slim image (or as a systemd unit on
a provisioned VPS), running alongside the proxy it steers.

## Runtime dependencies

Installed on the host / in the image (see the root `Dockerfile`):

- **nftables** (`nft`) — the runtime programs and tears down its own table.
- **ethtool** — used with `--iface` to disable NIC offloads on the steered link.

## Capabilities

The sidecar needs exactly two Linux capabilities, and the deployment must grant
no more:

| Capability      | Why                                                        |
| --------------- | ---------------------------------------------------------- |
| `CAP_NET_ADMIN` | program nftables, set the reinjection `SO_MARK`, `ethtool` |
| `CAP_NET_RAW`   | open the raw socket used to reinject outbound packets      |

In Docker: `--cap-add=NET_ADMIN --cap-add=NET_RAW`. Under systemd: see
`geneva-server.service` (`AmbientCapabilities`). No `--privileged`, no root
filesystem access, no other caps — the sidecar's blast radius stays off the
proxy's.

## Why `--iface` matters

NFQUEUE hands userspace packets from the kernel's egress path, *before*
segmentation and checksum offload run. Without disabling those offloads a queued
"packet" can be a super-segment many times the MTU, with a placeholder checksum —
neither of which survives raw-socket reinjection. `--iface <dev>` makes the
sidecar run `ethtool -K` to turn the offloads off, so NFQUEUE yields real,
MTU-sized, fully-checksummed packets. Always set it to the interface carrying the
proxy's traffic.

The offloads come down only while something is actually being steered, and go
back up when it stops — a sidecar with no strategy leaves the NIC alone.

## Modes

- **prod** — the assigned strategy on a fleet box:

  ```sh
  geneva-server run \
    --mode=prod \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

- **eval** — a candidate on a dedicated test box, with canary capture. The
  overlay agent assigns candidates through v1 and the GA reads the per-market
  canary pool from `GET /canary`:

  ```sh
  geneva-server run \
    --mode=eval --market=RU \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

Both modes use immutable per-connection generations. Existing flows retain
their conntrack generation through drain and rollback. Normal production startup
is inactive and accepts desired state through v1.

The control API is unauthenticated, so it must not listen on `0.0.0.0`. If an
overlay agent needs to reach it remotely, bind only a
dedicated management interface (e.g. a WireGuard/VPC address) and gate it with
network ACLs — never the public interface.

## Control / health surface

Bind `--control-addr` to a private address (localhost or a management network).

| Method + path   | Mode      | Purpose                                                     |
| --------------- | --------- | ----------------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, engine/verdict/inbound-TCP stats            |
| `GET /canary`   | eval only | per-market captured field-value pool                        |
| `GET /v1/adapter/descriptor` / `POST /v1/adapter/verify` | both | generic numeric v1 capabilities / artifact validation |
| `POST /v1/adapter/prepare` | both | validate and persist an immutable identity-bound deployment |
| `POST /v1/adapter/activate-for-new-connections` | both | stage union scopes, then flip new SYNs |
| `POST /v1/adapter/deactivate-for-new-connections` | both | identity-fenced stop of new assignments |
| `GET /v1/adapter/status` | both | generic active/prepared/draining identity state |
| `POST /v1/adapter/drain` / `POST /v1/adapter/garbage-collect` | both | bounded count, then keep-set collection |
| `POST /v1/adapter/rollback` | both | restage a complete previous-known-good artifact |

There is no scrape endpoint. Counters are exported as OTLP metrics to the box's
local collector and read from the fleet's backend (see "Metric export" below);
the surface here is only what a caller needs synchronously against one named
box. `/healthz` keeps the engine snapshot because the GA pre-screen decides
whether to keep a candidate within seconds of self-dialling it, which is shorter
than an export interval plus query lag.

The versioned lifecycle responses expose only a bare lowercase SHA-256 artifact
digest. Raw DNA remains solely in the mode-0600 reconstruction file. Keep this
surface loopback-only unless an authenticated management network protects it.
See [`../docs/adapter-v1.md`](../docs/adapter-v1.md) for exact request bodies,
numeric fields, keep-set GC, and retry semantics.

## Metric export

Export is opt-in via the standard `OTEL_EXPORTER_OTLP_*` environment variables,
set in `/etc/geneva-server/geneva.env` alongside `GENEVA_ARGS`. With no endpoint
configured the sidecar starts normally with metrics disabled — a box whose
collector is not up yet still steers traffic.

```sh
OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://127.0.0.1:4318/v1/metrics
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=prod,host.name=<box>
```

Use an **IPv4 literal**, not `localhost`: the systemd unit's
`RestrictAddressFamilies` deliberately omits `AF_INET6`, and `localhost` can
resolve to `::1`.

`service.name` is `geneva-server` and `service.version` is the build's VCS
revision; both can be overridden through `OTEL_SERVICE_NAME` /
`OTEL_RESOURCE_ATTRIBUTES`. Counters export with **delta** temporality, matching
the rest of the fleet — a test box being torn down and replaced (which happens
continuously as IPs burn) then reads as a series ending, not as a negative jump.

## Installing from a release

Tagged builds publish a `.deb` per architecture to GitHub Releases:

```
https://github.com/getlantern/geneva-server/releases/download/v<ver>/geneva-server_<ver>_linux_<arch>.deb
```

The package installs `/usr/local/bin/geneva-server`, the systemd unit at
`/usr/lib/systemd/system/geneva-server.service`, an empty
`/etc/geneva-server` (mode `0750`, group `geneva-server`), and depends on
`nftables` and `ethtool`. Its preinstall script creates the `geneva-server`
system account the unit runs as — without it systemd cannot deliver the two
ambient capabilities.

The unit ships **disabled**: it cannot start until the deployment has written
`/etc/geneva-server/geneva.env`. So
install, write the config, then `systemctl enable --now geneva-server`.

`main` auto-tags a patch release on any change to the binary or its packaging
(the workflow's path filter excludes tests, the e2e harness and this file, since
those produce an identical package).
The tag is pushed before the release build runs, so the newest tag is
installable only once its release workflow has published — during a build, or
after a failed one, the tag can exist with no assets. Assets are never
overwritten, so a published tag stays installable forever; there is no mutable
"latest" asset to pin against.

## Provisioning notes (bandit VPS)

Mirror the `lantern-box` provisioning flow:

1. Install the `.deb` for the target tag. `nftables` and `ethtool` come in as
   dependencies, so cloud-init does not install them separately (the
   `Dockerfile` bakes them into the image path instead).
2. Write `/etc/geneva-server/geneva.env` with `GENEVA_ARGS=...` and the
   `OTEL_EXPORTER_OTLP_*` endpoint. It must be readable by the `geneva-server` account
   (`root:geneva-server`, mode `0640`); the unit's `ProtectSystem=strict` makes
   all of `/etc` read-only to the process, so nothing else is needed to protect
   them.
3. `systemctl enable --now geneva-server.service`. `enable` alone would leave
   the sidecar stopped until the next boot.

In eval mode the sidecar starts with no strategy, steering nothing at all, until
the overlay agent prepares and activates an artifact through v1. A strategy
file is populated by the versioned lifecycle.

The nftables rules are runtime-owned: the sidecar programs its table from the
loaded strategy and deletes it on stop, so provisioning must **not** install
steering rules itself.

The systemd unit creates `/var/lib/geneva-server` for the default
`--adapter-state-file`; authoritative production rejects an empty path. This
0600 v2 file contains the DNA, phase, identity, and exact adapter protocol,
schema, and required runtime metadata of every live generation. Restart rebuilds
and validates all artifacts against the installed descriptor before loading any
assignment. Incompatible, metadata-less v1, or corrupt state is durably renamed
to a quarantine file. The local lifecycle remains reachable for remediation but
reports `unsafe`, `/healthz` returns unhealthy, no new generation is assigned,
and unknown flows bypass userspace. The overlay manager can repair with its
normal newer-snapshot `Prepare` → `Verify` → `ActivateForNewConnections`
sequence after Geneva freshly proves exact neutral kernel state and snapshots
conntrack; rollback remains available for a full known-good fallback. This proof
is process-local, repeated after every restart, and retryable in the same process
after transient startup proof failure or completed integrity reconciliation. Do
not edit or delete conntrack marks. Missing-engine signals are never coalesced
away merely because the adapter is already unsafe: a monotonic fault epoch
invalidates startup and recovery proofs, and retained live engines are rebuilt
and checked against durable DNA before activation can clear unhealthy state.

### Conntrack mark reservation and drain

The adapter reserves conntrack mask `0xfffff000` as `0x67GGGxxx`. `GGG` is a
12-bit generation ID and all low 12 bits are preserved. The audit found these
current Lantern users: `docker/src/socks-proxy/start.sh` uses packet marks
`0x438`/1088 for TPROXY, while phost's iptables/gateway updater uses low-valued
packet marks (route tables start at 745). No current Lantern rule saves those
marks to conntrack. Geneva still preserves them deliberately: SYN assignment is
`(ct mark & ~0xfffff000) | 0x67GGG000`, guarded so a foreign nonzero value in
the reserved mask is never replaced, while NFQUEUE conntrack metadata supplies
the generation without changing the skb mark. Ordinary verdicts, no-listener bypass
and queue-full fail-open therefore retain exact external marks, and coincidental
foreign `0x67...` packet marks are untouched. Raw reinjection keeps NFQUEUE's
exact original routing `SO_MARK` (`0x438`, `0x440`, or phost value) and avoids
requeue through the dedicated service socket UID.
A foreign nonzero value inside the reserved
high 20 bits is left alone and the connection is not steered.

Drain/status read conntrack over netlink, filter by the full Geneva generation
mask, then by original IPv4/TCP destination port. GC refuses an active
generation or any nonzero result. IDs are bounded to 1..4095 and cannot be
changed in place; an ID becomes reusable only after zero-flow GC, so wraparound
cannot bind an old conntrack entry to new DNA. Startup also reserves every live
orphan ID found in the namespace. Restaging an absent rollback artifact takes a
fresh bounded full dump and allocates only an ID proven to have zero flows;
unknown orphan IDs never enter the union rules or engine registry.

At most three generations are retained by default; change this deliberately
with `--max-generations` (1..32). The handshake-scoped and every-packet subsets
also have separate `--max-scoped-generations` (default three) and
`--max-every-packet-generations` (default two) limits. Prepare rejects when any
applicable budget is full, and status exposes the generation resource class.
Lifecycle status reports authoritative connection counts and bare lowercase
SHA-256 hex digests, never raw DNA. `/healthz` uses the cached lifecycle view and
does not dump conntrack, keeping routine probes bounded; an integrity latch
returns HTTP 503 while the local rollback endpoints remain available.
Generic recovery Prepare/Verify endpoints also remain available, but health
stays 503 until a safely staged activation succeeds.

## What gets steered

Steering follows the strategy, because the NFQUEUE round trip — not the
manipulation — is what the sidecar costs. Measured on a 1-vCPU box running
vless+REALITY, queueing every packet on the proxy's port cost 76% of a bulk
transfer's throughput *with no strategy loaded*, while a strategy that duplicated
every data packet cost only ~4% more than that.

A Geneva strategy hands back any packet its triggers do not match, byte for byte.
So the rules are narrowed to what can match:

| Strategy | Steered |
| --- | --- |
| no strategy (eval boot, or `PUT ""`) | nothing: no table, no rules, offloads untouched |
| triggers on TCP flags, e.g. `[TCP:flags:S]` | only those flag combinations, per direction |
| an outbound-only forest | outbound only; inbound stays in the kernel |
| a trigger nftables cannot express (`TCP:load`, `IP:ttl`, options) | everything on the port, in that direction |

`GET /healthz` reports this under `steering`, which is where to look first when a
box is unexpectedly fast or slow:

```json
"steering": {"steering": true, "outbound": "flags&0xff==0x02", "inbound": "none", "offloads_disabled": true}
```

### Cost of a strategy that touches every packet

A strategy whose triggers match bulk data cannot be scoped away — those packets
genuinely have to reach userspace. What the sidecar does about it is spend as
little as possible per packet: one `recvmsg` per batch of packets rather than
per packet, accept verdicts batched into one message per batch, rewritten
packets replaced in the queue rather than dropped and reinjected through a raw
socket (which also skips a second trip through netfilter), and no allocation per
packet on the hot path.

Two counters on `/healthz` say when the box is losing packets rather than
manipulating them:

| Counter | Meaning |
| --- | --- |
| `verdicts.overruns` | userspace netlink delivery reported ENOBUFS; affected packet count/outcomes are unknown and are not included in accepted/dropped |
| `verdicts.truncated` | the kernel copied only part of a packet, so it was accepted unmodified rather than manipulated as a fragment |

Both should be zero. Queue startup requires the kernel to acknowledge
`NFQA_CFG_F_FAIL_OPEN`, which accepts new arrivals after a bound kernel queue
fills; nft `bypass` separately protects the no-listener case. A nonzero
`overruns` means userspace delivery could not keep up with
the packet rate on this box; a nonzero `truncated` means the copy length is too
small for its traffic.

### The censor signal comes from nftables counters

Steering follows the strategy, so an outbound-only strategy delivers no inbound
packet to userspace — and the censor-reachability signal, the inbound
SYN-to-data ratio that estimates whether a box's IP has been burned, is about
inbound packets. Left there, scoping would have bought throughput by going
blind.

So the classification happens in the kernel instead. Whenever the sidecar has a
table, it also installs named counters and a chain that sorts arriving packets
into them — RST, SYN, FIN, data, ack_only, in that precedence, each rule
returning so every packet lands in exactly one — and reads the counters once per
export interval. **No packet is queued for the signal**, and it works the same in
prod and eval, with or without an inbound tree in the strategy. On by default;
`--censor-counters=false` falls back to the userspace classifier, which only sees
what the strategy already steers.

Two things the kernel path cannot count, and reports as zero:

- `undecodable` — a decode failure cannot happen to a packet nobody decodes.
- `fragment` — a non-initial fragment carries no TCP header to match a port
  against, so counting them would mean counting every fragment on the box for
  every port.

And one approximation: nftables cannot subtract one header field from another, so
"carries a payload" is `meta length > 80` rather than
`ip length - ihl*4 - dataoffset*4 > 0`. A pure ACK with 32 bytes of options is 72
bytes, so the threshold is safe; the failure mode is a data segment with fewer
than ~28 payload bytes counting as `ack_only`, which proxy traffic does not
produce.

The counters ride along with a table that exists for steering. They never keep
one alive on their own, so **a box with no strategy reports no censor signal** —
it also has nothing of ours in the kernel, which is the trade that makes an
unconfigured sidecar free. A box that should be reporting a burn rate is a box
that should have a strategy.

### `--observe-inbound` (eval mode only)

With the counters above providing the censor signal, this flag no longer has
anything to do with it. What it still buys is *packets* in userspace rather than
counts — which only the eval-mode canary pool wants, since that captures real
header field values for the GA brain to mutate against. Prod has no canary pool
at all, so in prod the flag would pay for something nothing reads: it is refused
outright at startup rather than warned about.

**What it costs, if you are wondering why prod may not have it.** One round trip
per *inbound* packet, so it tracks the inbound packet rate, not the byte rate —
which makes it almost free or ruinous depending on which way the box's bulk
traffic runs, and a prod box does not get to choose which its users generate:

| Workload | without | with | |
| --- | --- | --- | --- |
| download-heavy, handshake-only strategy | 105.1 MB/s | 105.0 MB/s | free |
| download-heavy, strategy tampering every data packet | 36.6 MB/s | 33.3 MB/s | −9% |
| **upload-heavy, handshake-only strategy** | **79.3 MB/s** | **47.4 MB/s** | **−40%** |

Measured on a 1-vCPU box (route `d711a4df`, vless+REALITY). A download's inbound
direction is nothing but stretch-ACKs — 18.9k inbound packets across 900 MB, one
per ~33 outbound data packets — so observing it is free. An upload's inbound
direction is the bulk stream, and then every packet pays.

An eval box carries no client traffic at all, so turning it on there costs
nothing worth counting — which is the other half of the argument for the mode
gate: the box that can afford the signal is the box that produces it for free.
