// SPDX-License-Identifier: Apache-2.0

//! Validation errors: the reasons an event fails to conform to the attestation
//! rules. Every variant is decidable from the event alone — no external event
//! need be fetched — which keeps validation stateless and cheap.

use core::fmt;

use crate::constants::{KIND, MARKER_ATTESTS};

/// A reason an event is not a conforming Event Timestamp Attestation.
///
/// Returned by [`crate::validate`]. The enum is `#[non_exhaustive]`: future
/// revisions may add variants without a breaking change, so downstream `match`
/// expressions should include a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The event kind is not [`KIND`]. Carries the observed kind.
    WrongKind(u16),
    /// The `content` field is not the empty string.
    NonEmptyContent,
    /// No `e` tag carries the [`MARKER_ATTESTS`] marker as its fourth element.
    MissingAttestsTag,
    /// More than one `e` tag carries the [`MARKER_ATTESTS`] marker. Carries the
    /// observed count.
    MultipleAttestsTags(usize),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind(kind) => {
                write!(f, "wrong event kind: expected {KIND}, found {kind}")
            }
            Self::NonEmptyContent => f.write_str("content must be the empty string"),
            Self::MissingAttestsTag => {
                write!(
                    f,
                    "missing the required `e` tag with marker `{MARKER_ATTESTS}`"
                )
            }
            Self::MultipleAttestsTags(count) => write!(
                f,
                "expected exactly one `e` tag with marker `{MARKER_ATTESTS}`, found {count}"
            ),
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::ValidationError;
    use crate::constants::{KIND, MARKER_ATTESTS};

    #[test]
    fn display_porte_l_information_discriminante() {
        let kind = ValidationError::WrongKind(7).to_string();
        assert!(kind.contains(&KIND.to_string()));
        assert!(kind.contains('7'));

        assert!(!ValidationError::NonEmptyContent.to_string().is_empty());

        assert!(ValidationError::MissingAttestsTag
            .to_string()
            .contains(MARKER_ATTESTS));

        let multiple = ValidationError::MultipleAttestsTags(3).to_string();
        assert!(multiple.contains(MARKER_ATTESTS));
        assert!(multiple.contains('3'));
    }

    #[test]
    fn implemente_std_error() {
        // Compile-time confirmation that the type is a usable std error.
        let boxed: Box<dyn std::error::Error> = Box::new(ValidationError::NonEmptyContent);
        assert!(!boxed.to_string().is_empty());
    }

    #[test]
    fn egalite_par_variante() {
        assert_eq!(ValidationError::WrongKind(1), ValidationError::WrongKind(1));
        assert_ne!(ValidationError::WrongKind(1), ValidationError::WrongKind(2));
        assert_ne!(
            ValidationError::MissingAttestsTag,
            ValidationError::NonEmptyContent
        );
    }
}
