# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not via public issues.

- Preferred: open a private advisory through GitHub's
  [private vulnerability reporting](https://github.com/sashite/nostamper.rs/security/advisories/new).
- Alternatively, contact the maintainers at the address listed on the
  repository.

Please include a description, affected versions, and a minimal reproduction
where possible. We aim to acknowledge a report within a few business days and to
coordinate a fix and disclosure timeline with you.

## Supported versions

The crate is pre-1.0. Security fixes target the latest published `0.x` release.

## Scope

This is a pure library with a deliberately small attack surface:

- It contains no `unsafe`, performs no network or filesystem I/O, and reads no
  clock.
- Its only untrusted-input path is event **validation**, which inspects
  already-parsed fields and is written to be total (panic-free) on any input —
  a property exercised by property tests and a fuzz target.

The following are **by design**, not vulnerabilities:

- An attestation's value depends on trust in its signer. This crate implements
  the primitive only and makes no trustlessness claim; designating authoritative
  signers is an application-layer concern.
- `validate` checks structural conformance, not the event's signature. Verifying
  signatures (`event.verify()`) is the consumer's responsibility.

Reports concerning the transitive dependency graph (for example a new RUSTSEC
advisory) are welcome; the graph is monitored in CI via `cargo-deny`.
