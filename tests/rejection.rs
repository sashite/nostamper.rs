// SPDX-License-Identifier: Apache-2.0

//! Rejection — black-box tests that [`validate`] rejects each non-conformance,
//! one case per [`ValidationError`] variant. Non-conforming events are built
//! with the raw `nostr` API, since the crate's builder cannot produce them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nostamper::{validate, ValidationError, KIND, MARKER_ATTESTS};
use nostr::prelude::*;

const ATTESTED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn signed(kind: u16, content: &str, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .sign_with_keys(&Keys::generate())
        .unwrap()
}

fn attests_tag(id: &str) -> Tag {
    Tag::parse(["e", id, "", MARKER_ATTESTS]).unwrap()
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
    let other = Tag::parse(["e", ATTESTED, "", "root"]).unwrap();
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
