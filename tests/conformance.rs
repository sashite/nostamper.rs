// SPDX-License-Identifier: Apache-2.0

//! Conformance — black-box tests of the public API: an attestation built by the
//! crate satisfies the spec's MUST rules, and the consumer-side helpers behave.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nostamper::{
    attested_event_id, is_temporally_consistent, validate, AttestationBuilder, KIND, MARKER_ATTESTS,
};
use nostr::prelude::*;

const ATTESTED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn relay() -> RelayUrl {
    RelayUrl::parse("wss://relay.example.com").unwrap()
}

fn attests_tag_count(event: &Event) -> usize {
    event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().get(3).map(String::as_str) == Some(MARKER_ATTESTS))
        .count()
}

#[test]
fn une_attestation_construite_satisfait_les_regles_must() {
    let keys = Keys::generate();
    let attested = EventId::parse(ATTESTED).unwrap();

    let event = AttestationBuilder::new(attested)
        .relay_hint(relay())
        .to_event_builder()
        .finalize(&keys)
        .unwrap();

    // Règles MUST de la spec : kind 3410, content vide, exactement un tag attests.
    assert_eq!(event.kind, Kind::Custom(KIND));
    assert!(event.content.is_empty());
    assert_eq!(attests_tag_count(&event), 1);

    assert_eq!(validate(&event), Ok(()));
    assert_eq!(attested_event_id(&event), Some(attested));
}

#[test]
fn contexte_et_p_restent_conformes() {
    let keys = Keys::generate();
    let other = Keys::generate();
    let attested = EventId::parse(ATTESTED).unwrap();
    let root = EventId::parse(ROOT).unwrap();

    let event = AttestationBuilder::new(attested)
        .relay_hint(relay())
        .context(root, Some(relay()), "sashite:session")
        .notify(other.public_key())
        .to_event_builder()
        .finalize(&keys)
        .unwrap();

    // Le contexte ajoute un second tag `e`, mais un seul porte `attests`.
    assert_eq!(attests_tag_count(&event), 1);
    assert_eq!(validate(&event), Ok(()));
    assert_eq!(attested_event_id(&event), Some(attested));
}

#[test]
fn coherence_temporelle_via_api_publique() {
    let keys = Keys::generate();
    let event = AttestationBuilder::new(EventId::parse(ATTESTED).unwrap())
        .created_at(Timestamp::from(1_000))
        .to_event_builder()
        .finalize(&keys)
        .unwrap();

    assert!(is_temporally_consistent(&event, Timestamp::from(1_000)));
    assert!(is_temporally_consistent(&event, Timestamp::from(999)));
    assert!(!is_temporally_consistent(&event, Timestamp::from(1_001)));
}
