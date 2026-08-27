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

## Modes

- **prod** — one fixed strategy on a fleet box; reload by restart:

  ```
  geneva-server run \
    --mode=prod \
    --strategy-file=/etc/geneva-server/strategy.dna \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

- **eval** — a replaceable candidate on a dedicated test box, with canary
  capture. The GA brain assigns candidates via `PUT /strategy` and reads the
  per-market canary pool from `GET /canary`:

  ```
  geneva-server run \
    --mode=eval --market=RU \
    --port=443 --iface=eth0 \
    --control-addr=127.0.0.1:8092
  ```

  The control API is unauthenticated, so it must not listen on `0.0.0.0`: on an
  eval box, `PUT /strategy` lets any reachable client replace the active strategy
  and read canary data. If the GA brain needs to reach it remotely, bind only a
  dedicated management interface (e.g. a WireGuard/VPC address) and gate it with
  network ACLs — never the public interface.

## Control / health surface

Bind `--control-addr` to a private address (localhost or a management network).

| Method + path   | Mode      | Purpose                                             |
| --------------- | --------- | --------------------------------------------------- |
| `GET /healthz`  | both      | liveness + mode, strategy, engine & verdict stats   |
| `GET /metrics`  | both      | overhead measurements for GA pre-screen             |
| `GET /strategy` | both      | current strategy DNA                                |
| `PUT /strategy` | eval only | assign/replace a candidate (validated before apply) |
| `GET /canary`   | eval only | per-market captured field-value pool                |

## Provisioning notes (bandit VPS)

Mirror the `lantern-box` provisioning flow:

1. Install `nftables` and `ethtool` in `provision.sh` (or bake them into the
   image — the `Dockerfile` already does).
2. Write `/etc/geneva-server/geneva.env` with `GENEVA_ARGS=...` and the strategy
   file via cloud-init.
3. Enable `geneva-server.service`.

The nftables rules are runtime-owned: the sidecar creates its table on start and
deletes it on stop, so provisioning must **not** install steering rules itself.
