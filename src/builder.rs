// SPDX-License-Identifier: Apache-2.0

//! Building — the write path.
//!
//! [`AttestationBuilder`] assembles a conforming attestation from the author's
//! own inputs. It is **infallible**: tags are built with the verbatim
//! [`Tag::custom`] constructor (never the fallible parser), and relay hints are
//! taken as typed [`RelayUrl`] values — so validation happens at the caller's
//! boundary, and construction itself has no error path. The terminal
//! [`AttestationBuilder::to_event_builder`] yields an unsigned [`EventBuilder`]
//! that the caller signs with any signer (direct keys, NIP-07, NIP-46).

use nostr::{EventBuilder, EventId, Kind, PublicKey, RelayUrl, Tag, TagKind, Timestamp};

use crate::constants::{KIND, MARKER_ATTESTS};

/// An application-specific context reference, emitted as an additional `e` tag.
#[derive(Debug, Clone)]
struct ContextRef {
    event_id: EventId,
    relay_hint: Option<RelayUrl>,
    marker: String,
}

/// A builder for a conforming Event Timestamp Attestation.
///
/// Set the optional relay hint and any application context, then call
/// [`AttestationBuilder::to_event_builder`] to obtain an unsigned
/// [`EventBuilder`] ready to sign.
#[derive(Debug, Clone)]
pub struct AttestationBuilder {
    attested: EventId,
    relay_hint: Option<RelayUrl>,
    context: Vec<ContextRef>,
    notify: Vec<PublicKey>,
    created_at: Option<Timestamp>,
}

impl AttestationBuilder {
    /// Starts an attestation referencing `attested` (the event being witnessed).
    #[must_use]
    pub fn new(attested: EventId) -> Self {
        Self {
            attested,
            relay_hint: None,
            context: Vec::new(),
            notify: Vec::new(),
            created_at: None,
        }
    }

    /// Sets the relay hint for the attested-event `e` tag. The spec recommends
    /// (SHOULD) providing one so consumers can locate the attested event.
    #[must_use]
    pub fn relay_hint(mut self, url: RelayUrl) -> Self {
        self.relay_hint = Some(url);
        self
    }

    /// Adds an application-specific context reference as an additional `e` tag.
    ///
    /// `marker` SHOULD be namespaced with a short application or domain prefix
    /// (for example `"sashite:session"` or `"chess:root"`) and never a bare
    /// generic name such as `"context"` or `"anchor"`, to avoid collisions with
    /// future general-purpose markers. It MUST NOT be the reserved
    /// [`MARKER_ATTESTS`] marker — that tag is emitted automatically for the
    /// attested event, and reusing it would produce two `attests` tags and a
    /// non-conforming attestation.
    #[must_use]
    pub fn context(
        mut self,
        event_id: EventId,
        relay_hint: Option<RelayUrl>,
        marker: impl Into<String>,
    ) -> Self {
        self.context.push(ContextRef {
            event_id,
            relay_hint,
            marker: marker.into(),
        });
        self
    }

    /// Adds a `p` tag, for notification routing or indexing of an interested
    /// party. It carries no attestation semantics.
    #[must_use]
    pub fn notify(mut self, pubkey: PublicKey) -> Self {
        self.notify.push(pubkey);
        self
    }

    /// Overrides the attestation timestamp. By default the event is stamped at
    /// signing time; the attestation's `created_at` is the signer's claimed
    /// receipt moment for the attested event.
    #[must_use]
    pub fn created_at(mut self, timestamp: Timestamp) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Produces the unsigned [`EventBuilder`]. Sign it with any signer to obtain
    /// the attestation event. This step is infallible.
    #[must_use]
    pub fn to_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(e_tag(
            &self.attested,
            self.relay_hint.as_ref(),
            MARKER_ATTESTS,
        ));
        for reference in &self.context {
            tags.push(e_tag(
                &reference.event_id,
                reference.relay_hint.as_ref(),
                &reference.marker,
            ));
        }
        for pubkey in &self.notify {
            tags.push(Tag::custom(TagKind::p(), [pubkey.to_hex()]));
        }

        let mut builder = EventBuilder::new(Kind::Custom(KIND), "").tags(tags);
        if let Some(timestamp) = self.created_at {
            builder = builder.custom_created_at(timestamp);
        }
        builder
    }
}

/// Builds an `e` tag `["e", <id>, <relay-or-empty>, <marker>]` verbatim. The
/// relay slot is kept present (empty when unset) so the marker stays in the
/// fourth position per NIP-10.
fn e_tag(event_id: &EventId, relay_hint: Option<&RelayUrl>, marker: &str) -> Tag {
    let relay = relay_hint.map(RelayUrl::to_string).unwrap_or_default();
    Tag::custom(TagKind::e(), [event_id.to_hex(), relay, marker.to_string()])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::AttestationBuilder;
    use crate::constants::{KIND, MARKER_ATTESTS};
    use crate::{attested_event_id, validate};
    use nostr::prelude::*;

    const ATTESTED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn attested_id() -> EventId {
        EventId::parse(ATTESTED).unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example.com").unwrap()
    }

    #[test]
    fn attestation_minimale_est_conforme() {
        let keys = Keys::generate();
        let event = AttestationBuilder::new(attested_id())
            .relay_hint(relay())
            .to_event_builder()
            .sign_with_keys(&keys)
            .unwrap();

        event.verify().unwrap();
        assert_eq!(event.kind, Kind::Custom(KIND));
        assert!(event.content.is_empty());
        assert_eq!(validate(&event), Ok(()));
        assert_eq!(attested_event_id(&event), Some(attested_id()));
    }

    #[test]
    fn marqueur_attests_en_quatrieme_position() {
        let keys = Keys::generate();
        let event = AttestationBuilder::new(attested_id())
            .relay_hint(relay())
            .to_event_builder()
            .sign_with_keys(&keys)
            .unwrap();

        let slice = event.tags.iter().next().unwrap().as_slice();
        assert_eq!(slice[0], "e");
        assert_eq!(slice[3], MARKER_ATTESTS);
    }

    #[test]
    fn creneau_relais_vide_si_absent() {
        let keys = Keys::generate();
        let event = AttestationBuilder::new(attested_id())
            .to_event_builder()
            .sign_with_keys(&keys)
            .unwrap();

        // Sans relay_hint : le créneau (3e) est vide, le marqueur reste 4e.
        let slice = event.tags.iter().next().unwrap().as_slice();
        assert_eq!(slice[2], "");
        assert_eq!(slice[3], MARKER_ATTESTS);
        assert_eq!(validate(&event), Ok(()));
    }

    #[test]
    fn contexte_et_p_preservent_la_conformite() {
        let keys = Keys::generate();
        let other = Keys::generate();
        let root = EventId::parse(ROOT).unwrap();
        let event = AttestationBuilder::new(attested_id())
            .relay_hint(relay())
            .context(root, Some(relay()), "sashite:session")
            .notify(other.public_key())
            .to_event_builder()
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(validate(&event), Ok(()));

        let markers: Vec<String> = event
            .tags
            .iter()
            .filter_map(|tag| tag.as_slice().get(3).cloned())
            .collect();
        assert!(markers.contains(&MARKER_ATTESTS.to_owned()));
        assert!(markers.contains(&"sashite:session".to_owned()));

        let has_p = event
            .tags
            .iter()
            .any(|tag| tag.as_slice().first().map(String::as_str) == Some("p"));
        assert!(has_p);
    }

    #[test]
    fn created_at_personnalise() {
        let keys = Keys::generate();
        let when = Timestamp::from(1_700_000_000);
        let event = AttestationBuilder::new(attested_id())
            .created_at(when)
            .to_event_builder()
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(event.created_at, when);
    }
}
