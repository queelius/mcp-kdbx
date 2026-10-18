//! The core error type.
//!
//! `CoreError` carries a typed [`ErrorCode`], a human-readable message, and an
//! optional structured `details` payload. The MCP adapter (Phase 3) maps it
//! straight onto the protocol error envelope `{ code, message, details }` from
//! spec section 1.
//!
//! The code set is a typed enum, not free strings, so the wire contract is
//! derived from one place: add a variant to [`ErrorCode`], implement its
//! `as_str`, and every layer that reports it stays in sync. There is no
//! parallel string table to keep aligned.

use serde_json::Value;
use std::fmt;

/// Every error code in the v0.1 tool surface (spec section 1, "Error code
/// enumeration"). The `as_str` form is the stable wire contract; do not change
/// an existing string without a major version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    VaultLocked,
    VaultAlreadyUnlocked,
    VaultNotFound,
    AuthFailed,
    UnlockSourceMissing,
    GroupNotFound,
    EntryNotFound,
    FieldNotFound,
    FieldNotProtected,
    AttachmentNotFound,
    NoOtpConfigured,
    WritesDisabled,
    NoPendingChanges,
    WriteFailed,
    VaultFileModified,
    EntryTitleInvalid,
    FieldNameInvalid,
    /// A caller-supplied value was malformed in a way the other codes do not
    /// name (for example, an attachment whose base64 fails to decode). Distinct
    /// from `FIELD_NAME_INVALID`, which is specifically about a bad field name.
    InvalidInput,
    /// A vault path is not well-formed (no leading `/`, an empty `//` segment,
    /// a dangling `\` escape, a `:0` ordinal). Distinct from `GROUP_NOT_FOUND`
    /// and `ENTRY_NOT_FOUND`, which mean a well-formed path matched nothing.
    PathInvalid,
    /// The vault file could not be opened for a reason found before any key
    /// is checked (not a KDBX file, an unsupported version, truncated, or a
    /// corrupt header), so reporting it reveals nothing about the password.
    /// `details.reason` names which. A wrong key stays `AUTH_FAILED`.
    VaultUnreadable,
}

impl ErrorCode {
    /// The stable wire string for this code.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::VaultLocked => "VAULT_LOCKED",
            ErrorCode::VaultAlreadyUnlocked => "VAULT_ALREADY_UNLOCKED",
            ErrorCode::VaultNotFound => "VAULT_NOT_FOUND",
            ErrorCode::AuthFailed => "AUTH_FAILED",
            ErrorCode::UnlockSourceMissing => "UNLOCK_SOURCE_MISSING",
            ErrorCode::GroupNotFound => "GROUP_NOT_FOUND",
            ErrorCode::EntryNotFound => "ENTRY_NOT_FOUND",
            ErrorCode::FieldNotFound => "FIELD_NOT_FOUND",
            ErrorCode::FieldNotProtected => "FIELD_NOT_PROTECTED",
            ErrorCode::AttachmentNotFound => "ATTACHMENT_NOT_FOUND",
            ErrorCode::NoOtpConfigured => "NO_OTP_CONFIGURED",
            ErrorCode::WritesDisabled => "WRITES_DISABLED",
            ErrorCode::NoPendingChanges => "NO_PENDING_CHANGES",
            ErrorCode::WriteFailed => "WRITE_FAILED",
            ErrorCode::VaultFileModified => "VAULT_FILE_MODIFIED",
            ErrorCode::EntryTitleInvalid => "ENTRY_TITLE_INVALID",
            ErrorCode::FieldNameInvalid => "FIELD_NAME_INVALID",
            ErrorCode::InvalidInput => "INVALID_INPUT",
            ErrorCode::PathInvalid => "PATH_INVALID",
            ErrorCode::VaultUnreadable => "VAULT_UNREADABLE",
        }
    }

    /// A default human-readable message. Handlers may override it with more
    /// specific context via [`CoreError::with_message`].
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::VaultLocked => "Vault is locked. Call kdbx_unlock first.",
            ErrorCode::VaultAlreadyUnlocked => "Vault is already unlocked.",
            ErrorCode::VaultNotFound => "Vault file not found.",
            ErrorCode::AuthFailed => "Authentication failed: wrong password or keyfile.",
            ErrorCode::UnlockSourceMissing => {
                "No password provided and no unlock source is configured."
            }
            ErrorCode::GroupNotFound => "No group resolves at that path.",
            ErrorCode::EntryNotFound => "No entry resolves at that path.",
            ErrorCode::FieldNotFound => "The entry has no field by that name.",
            ErrorCode::FieldNotProtected => {
                "That field is not protected; read it with a list or get tool instead of a reveal."
            }
            ErrorCode::AttachmentNotFound => "The entry has no attachment by that name.",
            ErrorCode::NoOtpConfigured => "The entry has no TOTP configuration.",
            ErrorCode::WritesDisabled => {
                "Writes are disabled. Start the server with KDBX_ALLOW_WRITES=true to enable them."
            }
            ErrorCode::NoPendingChanges => "There are no pending changes to save.",
            ErrorCode::WriteFailed => "Writing the vault to disk failed.",
            ErrorCode::VaultFileModified => "The vault file changed on disk since it was unlocked.",
            ErrorCode::EntryTitleInvalid => "The entry title is invalid.",
            ErrorCode::FieldNameInvalid => "The field name is invalid.",
            ErrorCode::InvalidInput => "A supplied value is invalid.",
            ErrorCode::PathInvalid => {
                "The path is malformed. Paths start with '/', separate groups with '/', escape a literal '/' as '\\/' and '\\' as '\\\\', and may end a segment with ':N' to pick the Nth same-named sibling."
            }
            ErrorCode::VaultUnreadable => {
                "The vault file is not a readable KDBX database (see details.reason)."
            }
        }
    }
}

/// Serializes as the stable wire string (the audit `auth_failed.error_code`).
impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A tool-surface error: a typed code plus a message and optional details.
///
/// Construct the common case with `CoreError::new(ErrorCode::GroupNotFound)`,
/// then chain `.with_message(...)` and/or `.with_details(json!({...}))` when a
/// handler has more to say. `ErrorCode` also `Into<CoreError>` for the bare
/// case, so `return Err(ErrorCode::VaultLocked.into())` works.
#[derive(Debug, Clone)]
pub struct CoreError {
    code: ErrorCode,
    message: String,
    details: Option<Value>,
}

impl CoreError {
    /// Build an error from a code, using the code's default message.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.default_message().to_string(),
            details: None,
        }
    }

    /// Replace the message with handler-specific context.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Attach a structured details payload (surfaces under `error.details`).
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    /// The stable wire string for this error's code.
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }

    /// The typed code, for matching in tests and handlers.
    pub fn code_enum(&self) -> ErrorCode {
        self.code
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The structured details payload, if any.
    pub fn details(&self) -> Option<&Value> {
        self.details.as_ref()
    }
}

impl From<ErrorCode> for CoreError {
    fn from(code: ErrorCode) -> Self {
        CoreError::new(code)
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CoreError {}

/// Shorthand for the result type used throughout `engine`.
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The full set of codes in the v0.1 enumeration, paired with their wire
    /// strings. If a variant is added without a string, the exhaustive match in
    /// `as_str` fails to compile, and this list catches a wrong mapping.
    const ALL: &[(ErrorCode, &str)] = &[
        (ErrorCode::VaultLocked, "VAULT_LOCKED"),
        (ErrorCode::VaultAlreadyUnlocked, "VAULT_ALREADY_UNLOCKED"),
        (ErrorCode::VaultNotFound, "VAULT_NOT_FOUND"),
        (ErrorCode::AuthFailed, "AUTH_FAILED"),
        (ErrorCode::UnlockSourceMissing, "UNLOCK_SOURCE_MISSING"),
        (ErrorCode::GroupNotFound, "GROUP_NOT_FOUND"),
        (ErrorCode::EntryNotFound, "ENTRY_NOT_FOUND"),
        (ErrorCode::FieldNotFound, "FIELD_NOT_FOUND"),
        (ErrorCode::FieldNotProtected, "FIELD_NOT_PROTECTED"),
        (ErrorCode::AttachmentNotFound, "ATTACHMENT_NOT_FOUND"),
        (ErrorCode::NoOtpConfigured, "NO_OTP_CONFIGURED"),
        (ErrorCode::WritesDisabled, "WRITES_DISABLED"),
        (ErrorCode::NoPendingChanges, "NO_PENDING_CHANGES"),
        (ErrorCode::WriteFailed, "WRITE_FAILED"),
        (ErrorCode::VaultFileModified, "VAULT_FILE_MODIFIED"),
        (ErrorCode::EntryTitleInvalid, "ENTRY_TITLE_INVALID"),
        (ErrorCode::FieldNameInvalid, "FIELD_NAME_INVALID"),
        (ErrorCode::InvalidInput, "INVALID_INPUT"),
        (ErrorCode::PathInvalid, "PATH_INVALID"),
        (ErrorCode::VaultUnreadable, "VAULT_UNREADABLE"),
    ];

    #[test]
    fn every_code_maps_to_its_wire_string() {
        for (code, expected) in ALL {
            assert_eq!(code.as_str(), *expected);
            assert_eq!(CoreError::new(*code).code(), *expected);
        }
    }

    #[test]
    fn wire_strings_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for (_, s) in ALL {
            assert!(seen.insert(*s), "duplicate wire string: {s}");
        }
    }

    #[test]
    fn default_messages_are_nonempty() {
        for (code, _) in ALL {
            assert!(!code.default_message().is_empty());
        }
    }

    #[test]
    fn builder_overrides_message_and_attaches_details() {
        let err = CoreError::new(ErrorCode::GroupNotFound)
            .with_message("no group at /Web/Nope")
            .with_details(json!({ "path": "/Web/Nope" }));
        assert_eq!(err.code(), "GROUP_NOT_FOUND");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
        assert_eq!(err.message(), "no group at /Web/Nope");
        assert_eq!(err.details(), Some(&json!({ "path": "/Web/Nope" })));
    }

    #[test]
    fn errorcode_into_coreerror_uses_default_message() {
        let err: CoreError = ErrorCode::VaultLocked.into();
        assert_eq!(err.code(), "VAULT_LOCKED");
        assert_eq!(err.message(), ErrorCode::VaultLocked.default_message());
        assert!(err.details().is_none());
    }

    #[test]
    fn display_includes_code_and_message() {
        let err = CoreError::new(ErrorCode::AuthFailed);
        let shown = format!("{err}");
        assert!(shown.starts_with("AUTH_FAILED: "));
    }
}
