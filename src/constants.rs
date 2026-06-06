// SPDX-License-Identifier: Apache-2.0

//! Protocol constants: the on-wire "magic values", isolated here so they can be
//! audited at a glance and changed only deliberately. A regression test pins
//! them, so any edit to a wire value is a conscious, test-breaking act rather
//! than a silent accident.

/// The event kind for an Event Timestamp Attestation.
///
/// `1041` sits adjacent to NIP-03's `1040`, signalling a related concern —
/// event-level timestamping — under a different trust model. The value is
/// tentative pending a NIP assignment; implementers should confirm it is
/// unclaimed before adoption.
pub const KIND: u16 = 1041;

/// The marker required on the `e` tag that references the attested event, as
/// that tag's fourth element, following the NIP-10 marker convention.
pub const MARKER_ATTESTS: &str = "attests";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{KIND, MARKER_ATTESTS};

    #[test]
    fn valeurs_de_protocole_figees() {
        // The wire values are part of the protocol contract: pinning them turns
        // any change into a deliberate, test-breaking decision.
        assert_eq!(KIND, 1041);
        assert_eq!(MARKER_ATTESTS, "attests");
    }
}
