// SPDX-License-Identifier: Apache-2.0

//! Event Timestamp Attestations for Nostr — NIP-XXXX, kind `1041`.
//!
//! **Status — proposed NIP.** This implements a NIP currently under review
//! ([nostr-protocol/nips#2359](https://github.com/nostr-protocol/nips/pull/2359))
//! and **not yet accepted**. The kind number `1041` is tentative and the wire
//! format may change until the proposal is merged; pin an exact version and
//! review the proposal before relying on it in production.
//!
//! An *Event Timestamp Attestation* is a signed Nostr event that references
//! another event and whose `created_at` is the signer's claimed receipt moment
//! for it. It is a lightweight, trusted-signer counterpart to NIP-03
//! (OpenTimestamps): immediate and infrastructure-free, at the cost of relying
//! on trust in the signer rather than on Bitcoin anchoring. The two are
//! complementary — an event may carry both.
//!
//! This crate implements the **primitive only**: [`AttestationBuilder`] builds
//! conforming attestations and [`validate`] checks events against the structural
//! rules. It is deliberately silent on *who* may produce authoritative
//! attestations for a given application — that is a higher layer's concern.
//!
//! # Conformance (stateless)
//!
//! A conforming attestation is an event of kind [`KIND`] with exactly one `e`
//! tag carrying the marker [`MARKER_ATTESTS`] as its fourth element (the
//! reference to the attested event) and an empty `content` field. Both are
//! decidable from the event alone — no external event need be fetched.
//! [`validate`] returns a [`ValidationError`] naming the first violated rule.
//! Additional `e` tags with namespaced markers and `p` tags are permitted and
//! ignored by validation.
//!
//! # Building
//!
//! [`AttestationBuilder`] assembles a conforming attestation from the author's
//! own inputs and yields an unsigned `EventBuilder` to sign with any signer
//! (direct keys, NIP-07, NIP-46):
//!
//! ```
//! use nostr::prelude::*;
//! use nostamper::{validate, AttestationBuilder};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let keys = Keys::generate();
//! let attested = EventId::parse(
//!     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//! )?;
//! let relay = RelayUrl::parse("wss://relay.example.com")?;
//!
//! let attestation = AttestationBuilder::new(attested)
//!     .relay_hint(relay)
//!     .to_event_builder()
//!     .sign_with_keys(&keys)?;
//!
//! assert!(validate(&attestation).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! # Consumer-side checks (stateful)
//!
//! Some properties require the attested event and are therefore not relay-level
//! rules. [`attested_event_id`] extracts the referenced id, and
//! [`is_temporally_consistent`] checks that the attestation does not predate the
//! event it witnesses. A consumer relying on an attestation MUST also verify its
//! signature (`event.verify()`) per NIP-01.
//!
//! # Safety and reliability
//!
//! The crate contains no `unsafe`, performs no I/O, and reads no clock. The
//! validation path consumes untrusted events but only *inspects* already-parsed
//! fields: it never reparses, never allocates on input size, and is total — the
//! crate's lint set forbids panic-capable operations on this path. Building is
//! infallible.

mod builder;
mod constants;
mod error;
mod validation;

pub use builder::AttestationBuilder;
pub use constants::{KIND, MARKER_ATTESTS};
pub use error::ValidationError;
pub use validation::{attested_event_id, is_temporally_consistent, validate};
