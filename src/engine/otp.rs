//! TOTP for a live entry, through kdbx-core's one implementation.
//!
//! kdbx-core owns TOTP (`kdbx_core::otp`): the three encodings (KeePassXC's
//! `otp` URI, KeePass 2's native `TimeOtp-*` fields, the legacy `TOTP Seed` /
//! `TOTP Settings` pair), decimal and Steam codes, bounds checks, and typed
//! errors for a malformed configuration. Snapshots seal the OTP secret, so
//! the plaintext comes from the live keepass entry through
//! `kdbx_core::capture::keepass_0_12::otp_fields`, which copies the
//! OTP-related fields and nothing else.
//!
//! This module only adapts that to mcp-kdbx: a missing configuration is
//! `Ok(None)` (the tool reports `NO_OTP_CONFIGURED`), a malformed one is
//! `OTP_INVALID` carrying kdbx-core's typed source and reason, and
//! [`has_otp`] is true exactly when a code could be produced.

use crate::engine::error::{CoreError, CoreResult, ErrorCode};
use kdbx_core::capture::keepass_0_12::otp_fields;
use kdbx_core::otp::{OtpError, TotpConfig, resolve_fields};
use std::time::{SystemTime, UNIX_EPOCH};

/// The TOTP configuration of `entry`: `Ok(None)` when it has none, and
/// `OTP_INVALID` when one is configured but no source is usable.
pub fn resolve(entry: &keepass::db::Entry) -> CoreResult<Option<TotpConfig>> {
    resolve_fields(&otp_fields(entry)).map_err(|e| otp_invalid(&e))
}

/// Whether `entry` has a usable TOTP configuration: the `has_otp` flag the
/// read views and the stage diff report, true exactly when `kdbx_get_otp`
/// would produce a code.
pub fn has_otp(entry: &keepass::db::Entry) -> bool {
    matches!(resolve(entry), Ok(Some(_)))
}

/// The current wall-clock time in Unix seconds (kdbx-core reads no clock). A
/// clock before the epoch (it should not be) reads as 0.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `OTP_INVALID` for a malformed configuration. The details are kdbx-core's
/// typed, serialized forms: `source` (`uri`, `keepass_native`, `legacy`) and
/// `reason` (for example `invalid_secret`, or `{"missing_field": "TOTP Seed"}`).
/// An error kind a later kdbx-core adds is reported in its own serialized form
/// under `error`.
fn otp_invalid(e: &OtpError) -> CoreError {
    let details = match e {
        OtpError::Malformed { source, reason } => {
            serde_json::json!({ "source": source, "reason": reason })
        }
        other => serde_json::json!({ "error": other }),
    };
    CoreError::new(ErrorCode::OtpInvalid)
        .with_message(format!("{e}. {}", ErrorCode::OtpInvalid.default_message()))
        .with_details(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;

    /// The first entry of a database holding one entry with these fields.
    fn entry_with(fields: &[(&str, &str)]) -> Database {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            for (name, value) in fields {
                e.set_protected(*name, *value);
            }
        });
        db
    }

    fn resolve_only(db: &Database) -> CoreResult<Option<TotpConfig>> {
        resolve(&db.iter_all_entries().next().expect("one entry"))
    }

    #[test]
    fn a_configured_uri_resolves_and_computes_the_rfc_vector() {
        let db = entry_with(&[(
            "otp",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        )]);
        let config = resolve_only(&db).unwrap().expect("configured");
        assert_eq!(config.code_at(59).code(), "287082");
        assert!(has_otp(&db.iter_all_entries().next().unwrap()));
    }

    #[test]
    fn no_source_is_none_and_not_an_error() {
        let db = entry_with(&[("Title", "plain")]);
        assert!(resolve_only(&db).unwrap().is_none());
        assert!(!has_otp(&db.iter_all_entries().next().unwrap()));
    }

    #[test]
    fn a_malformed_source_is_otp_invalid_with_typed_details() {
        let db = entry_with(&[("otp", "otpauth://hotp/x?secret=GEZDGNBV")]);
        let err = resolve_only(&db).unwrap_err();
        assert_eq!(err.code_enum(), ErrorCode::OtpInvalid);
        assert_eq!(
            err.details().unwrap(),
            &serde_json::json!({ "source": "uri", "reason": "not_totp" })
        );
        assert!(!has_otp(&db.iter_all_entries().next().unwrap()));
    }

    #[test]
    fn the_error_never_carries_the_secret() {
        let db = entry_with(&[
            ("TimeOtp-Secret-Base32", "SECRETMARK!!"),
            ("TimeOtp-Period", "0"),
        ]);
        let err = resolve_only(&db).unwrap_err();
        let rendered = format!("{err} {:?}", err.details());
        assert!(!rendered.contains("SECRETMARK"), "{rendered}");
    }
}
