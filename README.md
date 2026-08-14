# nostamper

Build and validate **Event Timestamp Attestations** (NIP-XXXX, kind `3410`) for
[Nostr](https://github.com/nostr-protocol/nostr).

> **Status — proposed NIP.** This crate implements *Event Timestamp Attestations*,
> a NIP currently under review ([nostr-protocol/nips#2359][pr]) and **not yet
> accepted**. The kind number `3410` is tentative and the wire format may change
> until the proposal is merged. Pin an exact version and review the [proposal][pr]
> before relying on it in production.
>
> [pr]: https://github.com/nostr-protocol/nips/pull/2359

An *Event Timestamp Attestation* is a signed event that references another event
and whose `created_at` is the signer's claimed receipt moment for it. It is a
lightweight, trusted-signer counterpart to
[NIP-03](https://github.com/nostr-protocol/nips/blob/master/03.md)
(OpenTimestamps): immediate and infrastructure-free, at the cost of relying on
trust in the signer rather than on Bitcoin anchoring. The two are complementary
— an event may carry both.

This crate implements the **primitive only**. It builds conforming attestations
and validates events against the structural rules; it is deliberately silent on
*who* may produce authoritative attestations for a given application, which is a
higher layer's concern.

## Conformance rules (stateless)

A conforming attestation is a kind-`3410` event with:

- exactly one `e` tag carrying the marker `attests` as its fourth element (the
  reference to the attested event), and
- an empty `content` field.

Both are decidable from the event alone — no external event need be fetched.
Additional `e` tags with namespaced markers (e.g. `sashite:session`) and `p`
tags are permitted and ignored by validation.

## Usage

```rust
use nostr::event::{EventId, FinalizeEvent};
use nostr::key::Keys;
use nostr::types::RelayUrl;
use nostamper::{validate, AttestationBuilder};

let keys = Keys::generate();
let attested = EventId::parse(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
)
.expect("valid event id");
let relay = RelayUrl::parse("wss://relay.example.com").expect("valid relay url");

// Build and sign (any signer works: direct keys, NIP-07, NIP-46).
let attestation = AttestationBuilder::new(attested)
    .relay_hint(relay)
    .to_event_builder()
    .finalize(&keys)
    .expect("signing succeeds");

// Stateless conformance check.
assert!(validate(&attestation).is_ok());
```

An application may attach context for discovery via an additional, namespaced
`e` tag (the marker must not be the reserved `attests`):

```rust
use nostr::event::EventId;
use nostr::types::RelayUrl;
use nostamper::AttestationBuilder;

let attested = EventId::parse(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
)
.expect("valid event id");
let root = EventId::parse(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
)
.expect("valid event id");
let relay = RelayUrl::parse("wss://relay.example.com").expect("valid relay url");

let builder = AttestationBuilder::new(attested)
    .relay_hint(relay.clone())
    .context(root, Some(relay), "sashite:session")
    .to_event_builder();
```

## Consumer-side (stateful) checks

Some properties require access to the attested event and are therefore *not*
relay-level rules:

- `is_temporally_consistent(&attestation, attested_created_at)` — the
  attestation must not predate the event it witnesses.
- Verify the attestation's signature (`event.verify()`) before relying on its
  `created_at`, and verify the attested event's own signature where available.

## Trust model

This crate provides **no** trustlessness guarantee. The value of an attestation
depends entirely on the consumer's trust in the signer. Applications making
high-value timing decisions should designate authoritative signers via a
higher-layer specification.

## Safety and reliability

- No `unsafe` (`unsafe_code = "forbid"`), no I/O, no clock access — pure
  functions.
- The validation path consumes untrusted events but only *inspects* fields that
  `nostr` has already parsed: it never reparses, never allocates on input size,
  and is **total**. The lint set denies panic-capable operations
  (`unwrap`/`expect`/`panic`/indexing/arithmetic) on this path, and a `proptest`
  suite plus a `cargo-fuzz` target exercise it on arbitrary input.
- Building is **infallible**.
- Supply chain is policed in CI by `cargo-deny` (advisories, licenses, sources).

### Running the fuzz target

The harness lives in `fuzz/`, a standalone workspace, and needs **nightly** —
`cargo-fuzz` passes `-Zsanitizer=address`. rustup picks the toolchain from the
*working directory*, and the repo-root `rust-toolchain.toml` pins stable, so
running `cargo fuzz` from the root selects stable and fails before compiling
anything ("the option `Z` is only accepted on the nightly compiler"). Run it
from inside `fuzz/`, where `fuzz/rust-toolchain.toml` applies:

```sh
rustup toolchain install nightly   # once
cd fuzz
cargo fuzz build                   # compile only — what CI checks
cargo fuzz run validate            # actually fuzz
```

From the repo root, force the toolchain instead — this is what the CI job does:

```sh
RUSTUP_TOOLCHAIN=nightly cargo fuzz build
```

## Status and MSRV

`nostr` `0.45`. Developed and tested on Rust `1.96`. See the status note near the
top of this document regarding the proposed NIP and the tentative `3410` kind.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
