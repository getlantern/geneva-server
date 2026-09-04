# Geneva loopback adapter protocol v1

Geneva implements the generic overlay adapter v1 lifecycle over local HTTP. It
has no lantern-cloud or gRPC dependency and must remain bound to loopback or an
equivalently protected management network.

`GET /v1/adapter/descriptor` returns the exact generic descriptor fields:

```json
{
  "adapter_protocol": 1,
  "technique": "geneva",
  "runtime_name": "geneva-engine",
  "runtime_version": "<exact build version>",
  "schema_versions": [1],
  "max_live_generations": 3
}
```

The cap is configurable from 1 through the generic maximum of 32 and defaults
to 3. The independent every-packet cap defaults to 2 so active/previous-known-
good plus a challenger can coexist; operators may lower or raise it explicitly
within the total cap.

## Artifact wire shape

Mutation requests use the generic immutable artifact directly. Numeric kernel
generation IDs are never caller-supplied; Geneva allocates and durably retains a
one-to-one mapping from artifact identity to conntrack generation.

```json
{
  "metadata": {
    "technique": "geneva",
    "revision": "overlay-revision-42",
    "content_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "size": 123,
    "adapter_protocol": 1,
    "required_runtime_name": "geneva-engine",
    "required_runtime_version": "<exact build version>",
    "schema_version": 1
  },
  "payload": "<base64 Geneva DNA>"
}
```

`content_sha256` and status identity `digest` are bare lowercase 64-character
SHA-256 hex over the exact decoded payload. The decoded artifact may be at most
256 KiB; the bounded HTTP envelope separately allows base64 and metadata
overhead. Preparing the same identity and content reuses its durable mapping.
The same identity with different content, or a second retained mapping for that
identity, is rejected.

## Operations

All mutations are `POST`; `descriptor` and `status` are `GET`.

- `/v1/adapter/prepare` accepts an artifact, validates resource budgets, creates
  its immutable engine, and durably allocates a private generation. While state
  is quarantined, a generic Prepare is accepted only after a process-local exact
  neutral-rules readback and fresh bounded full conntrack snapshot; proof
  failure changes no engine, nft, or durable state and is retryable. Prepare can
  establish the gate itself after a transient startup proof failure or after an
  asynchronous integrity reconciliation has finished and verified inactivity.
  The proof also reconstructs and verifies every retained live engine against
  durable DNA. A monotonic process-local epoch invalidates it on every integrity
  signal, including signals arriving before the repair guard exists.
- `/v1/adapter/verify` accepts the same artifact and confirms its exact prepared
  identity, content, runtime, schema, and digest.
- `/v1/adapter/activate-for-new-connections` accepts an artifact and assigns
  only future TCP SYNs after its union rules are installed and verified.
- `/v1/adapter/deactivate-for-new-connections` accepts an `ArtifactIdentity`.
  A delayed request for an identity which is no longer active is an idempotent
  no-op; it cannot deactivate a later artifact.
- `GET /v1/adapter/status` returns generic `active`, `prepared`, and `draining`
  identity lists. Draining entries contain bounded authoritative conntrack
  counts. Raw DNA and private numeric generations are absent.
- `/v1/adapter/drain` accepts an identity and returns `complete` plus
  `remaining_connections` from one controller-deadline-bounded count.
- `/v1/adapter/garbage-collect` accepts `{"keep":[<identity>, ...]}`. Active,
  draining, and explicitly kept artifacts survive. Only GC deletes an identity
  mapping and permits its private generation ID to be reused.
- `/v1/adapter/rollback` accepts the complete previous-known-good artifact. It
  can restage a retained drained artifact or recreate a GC'd artifact, is stable
  on retry, and remains an identity-fenced fallback after an integrity latch. A
  newer desired artifact may instead recover through the verified-neutral
  `Prepare` → `Verify` → `ActivateForNewConnections` path described below.
  Before allocating a private ID for an absent artifact, rollback takes one
  bounded full conntrack snapshot and selects only an ID authoritatively proven
  to have zero flows. Snapshot failure rejects it without preparing or steering.

Lifecycle mutation, status, drain, and garbage-collection handlers combine
request cancellation with a 30-second timeout. Every
conntrack dump has a shorter controller-owned hard deadline as well, including
startup reconstruction and internal callers.

## Ordering and crash safety

Activation first durably records reconstructable engine intent, then installs
and verifies the complete union of live generation scopes while the prior SYN
assignment remains unchanged, then atomically flips only the new-SYN assignment.
No generation can be assigned before its engine and queue rules exist.

First activation installs a temporary neutral new-SYN boundary and neutralizes
all relevant unowned conntracks before the flip. Every restart which observes a
durable active artifact repeats that neutral boundary and sweep before restoring
assignment. The restart has no intermediate unassigned transaction: the first
transaction already contains the complete live union, and the next transaction
changes it directly from neutral assignment to active assignment. This covers
crashes immediately after intent persistence and keeps
pre-existing established or half-open SYN-retransmit flows outside a newly
widened scope. Existing Geneva-marked live flows retain their generation.

State v2 durably stores the complete immutable artifact metadata, including the
adapter protocol, schema, and exact required runtime name/version. Restart
reconstructs each artifact and validates it against the installed descriptor
before loading any engine or assignment. Metadata-less v1, incompatible, or
corrupt state is durably renamed to a quarantine file; the adapter remains
reachable but inactive, unsafe, and unhealthy. A newer desired artifact can
remediate through the generic t8 sequence `Prepare` → `Verify` →
`ActivateForNewConnections`; a previous-known-good fallback may still use
`Rollback`. Prepare and Verify do not clear unsafe health. Only successful safe
activation clears the latch. The verified-neutral permission is never persisted
or trusted across restart: each process re-reads exact kernel state and takes a
fresh bounded namespace snapshot. Live orphan generation IDs remain reserved
and unruled until a later authoritative zero count.

State replacement requires temporary-file sync, atomic rename, and containing-
directory sync. A file or directory sync failure is integrity-fatal and cannot
authorize a kernel transition. Authoritative production rejects an empty
`--adapter-state-file`. Fatal integrity paths exit nonzero so the shipped
`Restart=on-failure` service restarts and reconciles; ordinary SIGTERM exits
cleanly after rules are removed while NFQUEUE ownership is still held.

Ambiguous nft command results are read back against the complete desired table.
If installation, deactivation, or compensation cannot be confirmed, Geneva
latches unsafe, removes new-SYN assignment or the table, and terminates rather
than continuing with uncertain steering. Integrity notification on the verdict
path only atomically latches and schedules this bounded reconciliation; packet
acceptance never waits for the lifecycle mutex or a conntrack dump.

Normal provisioned production starts inactive and is activated solely through
v1 desired state.
