// SPDX-License-Identifier: Apache-2.0

//! Protocol constants: the on-wire "magic values", isolated here so they can be
//! audited at a glance and changed only deliberately. A regression test pins
//! them, so any edit to a wire value is a conscious, test-breaking act rather
//! than a silent accident.

/// The event kind for an Event Timestamp Attestation.
///
/// `3410` sits in the block the consuming suite occupies (decision M-14,
/// 2026-08-11: renumbered from the NIP-03-adjacent `1041`, whose neighborhood
/// belongs to OpenTimestamps evolutions). Unclaimed in the upstream NIP
/// registry as of this crate's last revision.
pub const KIND: u16 = 3410;

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
        assert_eq!(KIND, 3410);
        assert_eq!(MARKER_ATTESTS, "attests");
    }
}
