// SPDX-License-Identifier: Apache-2.0

//! Validation — the untrusted-input path.
//!
//! These functions consume an [`Event`] that may come from anywhere (a relay, a
//! peer). This is the crate's only real attack surface, and it is kept minimal
//! by design:
//!
//! - **No reparsing.** The event has already been parsed and its signature
//!   already checkable by `nostr`; these functions only *inspect* typed fields.
//! - **No input-driven allocation.** Tag counting is a fold over the existing
//!   collection; nothing is allocated in proportion to the event's size.
//! - **Total.** Every operation is panic-free on any input — slice access goes
//!   through [`slice::first`]/[`slice::get`], never indexing, and there is no
//!   arithmetic. The crate lint set forbids panic-capable operations here.
//!
//! Structural conformance is distinct from signature validity: [`validate`]
//! checks the former only. A consumer relying on an attestation MUST also verify
//! the event's signature (`event.verify()`) per NIP-01.

use nostr::event::{Event, EventId, Kind, Tag};
use nostr::types::Timestamp;

use crate::constants::{KIND, MARKER_ATTESTS};
use crate::error::ValidationError;

/// Validates that `event` conforms to the attestation rules (stateless).
///
/// Checks, in order: the kind is [`KIND`], the `content` is empty, and exactly
/// one `e` tag carries the [`MARKER_ATTESTS`] marker as its fourth element.
///
/// This is a *structural* check only; it does not verify the event's signature.
///
/// # Errors
///
/// Returns the first violated [`ValidationError`].
pub fn validate(event: &Event) -> Result<(), ValidationError> {
    if event.kind != Kind::Custom(KIND) {
        return Err(ValidationError::WrongKind(event.kind.as_u16()));
    }
    if !event.content.is_empty() {
        return Err(ValidationError::NonEmptyContent);
    }
    match event
        .tags
        .iter()
        .filter(|tag| is_attests_e_tag(tag))
        .count()
    {
        0 => Err(ValidationError::MissingAttestsTag),
        1 => Ok(()),
        count => Err(ValidationError::MultipleAttestsTags(count)),
    }
}

/// Extracts the attested event id from `event`, if it carries the
/// `attests`-marked `e` tag and the referenced id parses.
///
/// Returns `None` for a non-conforming event; this function does not itself
/// validate conformance (call [`validate`] for that).
#[must_use]
pub fn attested_event_id(event: &Event) -> Option<EventId> {
    event
        .tags
        .iter()
        .find(|tag| is_attests_e_tag(tag))
        .and_then(|tag| tag.as_slice().get(1))
        .and_then(|hex| EventId::parse(hex.as_str()).ok())
}

/// Whether the attestation's `created_at` is logically consistent with the
/// attested event's `created_at`: a signer cannot receive an event before it
/// exists, so the attestation must not predate it.
///
/// This check is **stateful** — it requires the attested event's timestamp —
/// and is therefore a consumer-side concern, never a relay-level rule.
#[must_use]
pub fn is_temporally_consistent(attestation: &Event, attested_created_at: Timestamp) -> bool {
    attestation.created_at >= attested_created_at
}

/// Whether `tag` is an `e` tag carrying [`MARKER_ATTESTS`] as its fourth
/// element. Total on any tag shape: a tag shorter than four elements simply
/// fails the fourth-element check.
fn is_attests_e_tag(tag: &Tag) -> bool {
    let slice = tag.as_slice();
    slice.first().map(String::as_str) == Some("e")
        && slice.get(3).map(String::as_str) == Some(MARKER_ATTESTS)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{attested_event_id, is_temporally_consistent, validate};
    use crate::constants::{KIND, MARKER_ATTESTS};
    use crate::error::ValidationError;
    use nostr::prelude::*;

    const ATTESTED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn signed(kind: u16, content: &str, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(kind), content)
            .tags(tags)
            .finalize(&Keys::generate())
            .unwrap()
    }

    fn attests_tag(id: &str) -> Tag {
        Tag::parse(["e", id, "", MARKER_ATTESTS]).unwrap()
    }

    #[test]
    fn accepte_une_attestation_minimale() {
        let event = signed(KIND, "", vec![attests_tag(ATTESTED)]);
        assert_eq!(validate(&event), Ok(()));
    }

    #[test]
    fn rejette_mauvais_kind() {
        let event = signed(1, "", vec![attests_tag(ATTESTED)]);
        assert_eq!(validate(&event), Err(ValidationError::WrongKind(1)));
    }

    #[test]
    fn rejette_contenu_non_vide() {
        let event = signed(KIND, "payload", vec![attests_tag(ATTESTED)]);
        assert_eq!(validate(&event), Err(ValidationError::NonEmptyContent));
    }

    #[test]
    fn rejette_tag_attests_absent() {
        // Un tag `e` sans le marqueur `attests`.
        let other = Tag::parse(["e", ATTESTED, "", "mention"]).unwrap();
        let event = signed(KIND, "", vec![other]);
        assert_eq!(validate(&event), Err(ValidationError::MissingAttestsTag));
    }

    #[test]
    fn rejette_tags_attests_multiples() {
        let event = signed(KIND, "", vec![attests_tag(ATTESTED), attests_tag(ROOT)]);
        assert_eq!(
            validate(&event),
            Err(ValidationError::MultipleAttestsTags(2))
        );
    }

    #[test]
    fn total_sur_tag_court() {
        // Un tag `e` de deux éléments n'a pas de 4e position : il ne doit ni
        // paniquer ni compter comme `attests`.
        let short = Tag::parse(["e", ATTESTED]).unwrap();
        let event = signed(KIND, "", vec![short]);
        assert_eq!(validate(&event), Err(ValidationError::MissingAttestsTag));
    }

    #[test]
    fn attested_event_id_extrait_l_id() {
        let event = signed(KIND, "", vec![attests_tag(ATTESTED)]);
        assert_eq!(
            attested_event_id(&event),
            Some(EventId::parse(ATTESTED).unwrap())
        );
    }

    #[test]
    fn attested_event_id_absent_sans_tag() {
        let event = signed(KIND, "", vec![]);
        assert_eq!(attested_event_id(&event), None);
    }

    #[test]
    fn coherence_temporelle() {
        let event = EventBuilder::new(Kind::Custom(KIND), "")
            .tags([attests_tag(ATTESTED)])
            .custom_created_at(Timestamp::from(1_000))
            .finalize(&Keys::generate())
            .unwrap();

        assert!(is_temporally_consistent(&event, Timestamp::from(1_000)));
        assert!(is_temporally_consistent(&event, Timestamp::from(999)));
        assert!(!is_temporally_consistent(&event, Timestamp::from(1_001)));
    }
}
