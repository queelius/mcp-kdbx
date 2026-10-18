//! `Secret<T>`: a value that must never reach a log.
//!
//! Wrapping a field's type in `Secret` is how a struct says "this field holds
//! a secret" structurally, instead of by a hand-written `Debug` impl that each
//! new secret-bearing struct must remember to write:
//!
//! - `Debug` prints `<redacted>`, so a struct holding a `Secret` can derive
//!   `Debug` and a stray `tracing::debug!(?params)` still prints no secret.
//! - The inner value lives in [`Zeroizing`], so it is scrubbed when dropped.
//! - It deserializes transparently (the wire shape is the inner value's), and
//!   the adapter gives it a transparent JSON Schema, so tool input schemas are
//!   unchanged.
//! - It deliberately does not implement `Serialize` or `Display`: reading the
//!   value out takes an explicit [`Secret::expose`], which is easy to audit.
//!
//! `scripts/ci-audit.sh` (check D) relies on this: a secret-named field in a
//! struct that derives `Debug` must have a `Secret` type.

use zeroize::{Zeroize, Zeroizing};

/// A secret value: redacting `Debug`, zeroized on drop. See the module docs.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    /// Wrap a value.
    pub fn new(value: T) -> Self {
        Secret(Zeroizing::new(value))
    }

    /// Borrow the secret value. Every read of a secret goes through here.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Secret::new(value)
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de, T: Zeroize + serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Secret::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let s = Secret::new("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&s)), "Some(<redacted>)");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn deserializes_transparently() {
        let s: Secret<String> = serde_json::from_str("\"pw\"").unwrap();
        assert_eq!(s.expose(), "pw");
        let none: Option<Secret<String>> = serde_json::from_str("null").unwrap();
        assert!(none.is_none());
    }
}
