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
    --strategy-file=/etc/geneva-server/strategy.dna \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

- **eval** — a candidate on a dedicated test box, with canary capture. The GA
  brain assigns candidates via `PUT /strategy` and reads the per-market canary
  pool from `GET /canary`:

  ```sh
  geneva-server run \
    --mode=eval --market=RU \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

Both modes support updating the strategy **in place**: `PUT /strategy` validates
the DNA and swaps it atomically, taking effect on the next packet with no
restart. Delivering a strategy at boot (via `--strategy-file` + the config path)
and restarting also works.

The control API is unauthenticated, so it must not listen on `0.0.0.0`:
`PUT /strategy` lets any reachable client replace the active strategy on either a
prod or an eval box. If the GA brain needs to reach it remotely, bind only a
dedicated management interface (e.g. a WireGuard/VPC address) and gate it with
network ACLs — never the public interface.

## Control / health surface

Bind `--control-addr` to a private address (localhost or a management network).

| Method + path   | Mode      | Purpose                                                     |
| --------------- | --------- | ----------------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, strategy, engine/verdict/inbound-TCP stats |
| `GET /strategy` | both      | current strategy DNA                                        |
| `PUT /strategy` | both      | assign/replace the strategy in place (validated)            |
| `GET /canary`   | eval only | per-market captured field-value pool                        |

There is no scrape endpoint. Counters are exported as OTLP metrics to the box's
local collector and read from the fleet's backend (see "Metric export" below);
the surface here is only what a caller needs synchronously against one named
box. `/healthz` keeps the engine snapshot because the GA pre-screen decides
whether to keep a candidate within seconds of self-dialling it, which is shorter
than an export interval plus query lag.

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
`/etc/geneva-server/geneva.env`, and in prod mode the strategy file it names. So
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
   `OTEL_EXPORTER_OTLP_*` endpoint, plus — in prod mode — the strategy file
   `GENEVA_ARGS` names. Both must be readable by the `geneva-server` account
   (`root:geneva-server`, mode `0640`); the unit's `ProtectSystem=strict` makes
   all of `/etc` read-only to the process, so nothing else is needed to protect
   them.
3. `systemctl enable --now geneva-server.service`. `enable` alone would leave
   the sidecar stopped until the next boot.

In eval mode the strategy file is optional: the sidecar starts with no strategy,
steering nothing at all, until the GA brain assigns a candidate over
`PUT /strategy`.

The nftables rules are runtime-owned: the sidecar programs its table from the
loaded strategy and deletes it on stop, so provisioning must **not** install
steering rules itself.

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

### `--observe-inbound`

The censor-reachability signal (inbound SYN-to-data ratio, the estimate of a
box's IP being burned) needs inbound packets in userspace, which a strategy that
only acts outbound would not otherwise ask for. `--observe-inbound` keeps inbound
flowing while a strategy is loaded, at the cost of a round trip per inbound
packet — roughly half the packets on a busy proxy. It is off by default, and it
never overrides the no-strategy case: an idle sidecar stays off the data path.

An eval box carries no client traffic, so turning it on there costs nothing
worth counting. On a prod box it is a real throughput trade.
