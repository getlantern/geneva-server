# Geneva loopback adapter protocol v1

The adapter is a local HTTP implementation of the generic versioned lifecycle.
It has no lantern-cloud or gRPC dependency and must remain bound to loopback or
an equivalently protected management network.

`GET /v1/adapter/descriptor` returns numeric `protocol_version: 1`, numeric
`supported_schema_versions: [1]`, the exact string `runtime_version`, and
unsigned numeric artifact/generation caps. Geneva DNA uses schema version 1.
Artifacts are limited to 256 KiB after JSON decoding; the bounded JSON envelope
allows escaping overhead. The default retained-generation cap is 3 and the
protocol cap is 32.

Every deployment identity is immutable:

```json
{
  "generation": 7,
  "identity": {
    "technique": "geneva",
    "revision": "overlay-revision-42",
    "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

`digest` is bare lowercase 64-character SHA-256 hex over the exact decoded
artifact bytes. Lifecycle status, results, logs, and telemetry never contain raw
DNA. Raw DNA remains only in the explicitly legacy `/strategy` and `/healthz`
compatibility views and the mode-0600 reconstruction file.

Operations use `POST` unless noted:

- `/v1/adapter/verify`: `schema_version`, `deployment.identity`, and `artifact`.
  It parses and validates without changing state.
- `/v1/adapter/prepare`: `schema_version`, complete `deployment`, and `artifact`.
  Repeating the same identity/artifact is idempotent; an ID cannot be rebound.
- `/v1/adapter/activate-new`: complete target `deployment` and complete
  `expected_active` (or `{}` when inactive). A stale precondition is a conflict
  and makes no change. A successful retry is idempotent.
- `/v1/adapter/deactivate-new`: complete `expected_active`. It never removes
  draining scopes or resets connections. A delayed stale request cannot
  deactivate a later deployment.
- `GET /v1/adapter/status`: durable phase/digest/identity plus an authoritative,
  controller-deadline-bounded conntrack count for each active/draining
  generation. Routine `/healthz` does not dump conntrack.
- `/v1/adapter/drain`: complete `deployment`. `DrainResult` contains one bounded
  count, `drained`, and `checked_at`.
- `/v1/adapter/gc`: `keep` is a set of complete deployments. Only non-active,
  identity-matching, authoritative-zero-flow deployments outside that set are
  removed. A retained drained previous-known-good remains reactivatable.
- `/v1/adapter/rollback`: complete target `deployment` and complete
  `expected_active`. It is retry-stable and is the only activation permitted
  while an integrity fault is latched.

Each handler combines request cancellation with a 30-second server timeout.
Every conntrack operation also has an independent controller deadline, including
startup reconstruction. An integrity mismatch atomically latches unsafe state
on the packet path, accepts the current packet immediately, and performs one
bounded background deactivation. Until an identity-checked rollback succeeds,
new mutations are rejected synchronously.

Activation persists reconstructable engines first, verifies and installs the
union steering transaction while the previous assignment remains active, and
then performs a second atomic assignment transaction. First activation installs
a temporary neutral-SYN boundary and neutralizes existing relevant conntracks;
therefore a pre-existing or half-open flow cannot be captured by a widened
scope. Every nft write is read back using a fingerprint of the complete desired
table. An ambiguous command or failed compensation that cannot be confirmed
latches unsafe state and removes new-SYN assignment rather than continuing.
