// SPDX-License-Identifier: Apache-2.0

//! Properties — the reliability backbone, exercised with `proptest`.
//!
//! Two invariants over randomized inputs:
//!
//! 1. **Totality.** [`validate`] and [`attested_event_id`] never panic on an
//!    arbitrary *signed* event — any kind, any content, any tag shapes. This is
//!    the empirical face of the "zero attack surface" property; both functions
//!    are also confirmed deterministic (pure).
//! 2. **Round-trip.** Every event produced by [`AttestationBuilder`] is
//!    conforming, regardless of relay hint, context, notification, or
//!    timestamp; and its attested id round-trips through [`attested_event_id`].

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use nostamper::{attested_event_id, validate, AttestationBuilder};
use nostr::prelude::*;
use proptest::prelude::*;

/// Lowercase-hex encoding of 32 bytes (a valid `EventId` payload).
fn hex32(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A single tag element, biased toward protocol-significant tokens so the
/// generated tags frequently exercise the `attests` detection branches.
fn arb_element() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("e".to_owned()),
        Just("p".to_owned()),
        Just("attests".to_owned()),
        "[a-z0-9]{1,6}",
    ]
}

/// An arbitrary tag as a vector of 0..5 elements.
fn arb_tag_vec() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(arb_element(), 0..5)
}

proptest! {
    /// `validate` and `attested_event_id` are total (never panic) and pure
    /// (deterministic) on any signed event.
    #[test]
    fn validate_est_total_et_pur(
        kind in any::<u16>(),
        content in ".*",
        tags in proptest::collection::vec(arb_tag_vec(), 0..6),
    ) {
        let parsed: Vec<Tag> = tags.into_iter().filter_map(|t| Tag::parse(t).ok()).collect();
        let event = EventBuilder::new(Kind::Custom(kind), content)
            .tags(parsed)
            .sign_with_keys(&Keys::generate())
            .unwrap();

        // Ne paniquent jamais ; et sont déterministes (fonctions pures).
        prop_assert_eq!(validate(&event), validate(&event));
        prop_assert_eq!(attested_event_id(&event), attested_event_id(&event));
    }

    /// Anything the builder produces is conforming, and the attested id
    /// round-trips.
    #[test]
    fn builder_produit_toujours_conforme(
        attested_bytes in proptest::array::uniform32(any::<u8>()),
        with_relay in any::<bool>(),
        context in proptest::option::of((proptest::array::uniform32(any::<u8>()), "sashite:[a-z]{1,8}")),
        with_notify in any::<bool>(),
    ) {
        let attested = EventId::parse(hex32(attested_bytes).as_str()).unwrap();
        let mut builder = AttestationBuilder::new(attested);

        if with_relay {
            builder = builder.relay_hint(RelayUrl::parse("wss://relay.example.com").unwrap());
        }
        if let Some((context_bytes, marker)) = context {
            // Le marqueur de contexte n'est jamais `attests` (préfixe `sashite:`).
            let context_id = EventId::parse(hex32(context_bytes).as_str()).unwrap();
            builder = builder.context(context_id, None, marker);
        }
        if with_notify {
            builder = builder.notify(Keys::generate().public_key());
        }

        let event = builder
            .to_event_builder()
            .sign_with_keys(&Keys::generate())
            .unwrap();

        prop_assert!(validate(&event).is_ok());
        prop_assert_eq!(attested_event_id(&event), Some(attested));
    }
}
