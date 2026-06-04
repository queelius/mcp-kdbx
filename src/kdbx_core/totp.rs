//! otpauth URI parsing and TOTP code computation.
//!
//! Two sources feed a [`TotpConfig`]:
//!
//! - the modern `otpauth://totp/...` URI stored in an entry's `otp` field
//!   ([`TotpConfig::parse`]), and
//! - the legacy KeePass field pair `TOTP Seed` (base32 secret) plus
//!   `TOTP Settings` (a `period;digits` string), via
//!   [`TotpConfig::from_legacy`].
//!
//! Both parsers are provided here. The modern field takes priority, but this
//! module does not decide precedence: the Phase 3 caller resolves which source
//! an entry actually uses, then asks for a code. See spec section 3, "TOTP
//! semantics".
//!
//! The secret never leaves this process. Callers compute a code with
//! [`TotpConfig::compute_at`] (or [`TotpConfig::compute_now`]) and surface only
//! the resulting [`TotpCode`], whose shape is `{ code, valid_for_seconds,
//! period_seconds }`.
//!
//! The logic is ported from `web-kdbx/src/totp.rs`. Two differences:
//! the output field `seconds_remaining` is renamed to `valid_for_seconds` and
//! the period is echoed back as `period_seconds`, and a legacy field-pair
//! constructor is added that web-kdbx does not have.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};

/// A computed one-time code plus its remaining lifetime.
///
/// `code` is the current digits. `valid_for_seconds` counts down to the end of
/// the current time step (it equals `period_seconds` at the start of a step and
/// `1` on the last second). `period_seconds` echoes the step length so a caller
/// can render a progress indicator without re-reading the config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    /// The current one-time code, as a string of digits.
    pub code: String,
    /// Seconds left before the code rolls over to the next step.
    pub valid_for_seconds: u32,
    /// The configured step length in seconds (the TOTP period).
    pub period_seconds: u32,
}

/// The hash algorithm a TOTP config uses. Defaults to SHA1, the value assumed
/// when an otpauth URI omits the `algorithm` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP configuration: the decoded secret plus the parameters needed
/// to compute a code.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// The decoded (raw bytes) shared secret.
    pub secret: Vec<u8>,
    /// The time step in seconds.
    pub period: u32,
    /// The number of digits in the produced code.
    pub digits: u32,
    /// The hash algorithm.
    pub algo: TotpAlgo,
}

/// Smallest accepted time step. A `period` of zero would divide by zero in
/// [`TotpConfig::compute_at`] and inside totp_lite, so it is rejected.
const MIN_PERIOD: u32 = 1;

/// Largest accepted digit count. totp_lite computes the code modulo
/// `10^digits` in a `u64`, and `10^20` overflows `u64`, so anything past `10`
/// is both unrepresentable and far outside any real otpauth URI (the spec uses
/// 6 to 8). Capping here keeps an attacker-supplied `digits` from panicking
/// totp_lite via `pow` overflow.
const MAX_DIGITS: u32 = 10;

/// Reject a `period`/`digits` pair that would panic the code computation.
/// Used by both the otpauth and legacy constructors so the bounds live in one
/// place. Returns `None` when either value is out of range.
fn checked_params(period: u32, digits: u32) -> Option<()> {
    if period < MIN_PERIOD {
        return None;
    }
    if !(1..=MAX_DIGITS).contains(&digits) {
        return None;
    }
    Some(())
}

impl TotpConfig {
    /// Parse a modern `otpauth://totp/...` URI.
    ///
    /// Returns `None` when the input is not a URL, is not an `otpauth` scheme,
    /// is not a `totp` type (so `otpauth://hotp/...` is rejected), or carries no
    /// `secret`. The `period` (default 30), `digits` (default 6), and
    /// `algorithm` (default SHA1) parameters are optional. An unrecognized
    /// `algorithm` value falls back to SHA1.
    ///
    /// A `period` of 0 or a `digits` value outside `1..=10` is rejected
    /// (returns `None`). Those values come from untrusted vault content and
    /// would otherwise panic the code computation (divide by zero, or `pow`
    /// overflow), so a malformed entry yields no config rather than a crash.
    pub fn parse(uri: &str) -> Option<Self> {
        let url = url::Url::parse(uri).ok()?;
        if url.scheme() != "otpauth" {
            return None;
        }
        if url.host_str() != Some("totp") {
            return None;
        }

        let mut secret = None;
        let mut period = 30u32;
        let mut digits = 6u32;
        let mut algo = TotpAlgo::Sha1;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "secret" => {
                    secret = decode_base32_secret(v.as_ref());
                }
                "period" => {
                    if let Ok(p) = v.parse() {
                        period = p;
                    }
                }
                "digits" => {
                    if let Ok(d) = v.parse() {
                        digits = d;
                    }
                }
                "algorithm" => {
                    algo = parse_algo(v.as_ref());
                }
                _ => {}
            }
        }

        checked_params(period, digits)?;

        Some(Self {
            secret: secret?,
            period,
            digits,
            algo,
        })
    }

    /// Build a config from the legacy KeePass field pair.
    ///
    /// `seed` is the base32-encoded secret from the `TOTP Seed` field. `settings`
    /// is the `TOTP Settings` field, a `period;digits` string (for example
    /// `30;6`). The legacy convention is always SHA1.
    ///
    /// Returns `None` when the seed is empty or not valid base32, or when the
    /// settings string is not two numbers separated by a `;`. Whitespace around
    /// each part is tolerated. The modern otpauth field takes priority over this
    /// legacy pair; the caller decides which source to read.
    ///
    /// A `period` of 0 or a `digits` value outside `1..=10` is rejected
    /// (returns `None`), for the same reason as [`TotpConfig::parse`]: a legacy
    /// settings string like `0;6` or `30;20` comes from untrusted vault content
    /// and would otherwise panic the code computation.
    pub fn from_legacy(seed: &str, settings: &str) -> Option<Self> {
        let secret = decode_base32_secret(seed.trim())?;
        if secret.is_empty() {
            return None;
        }

        let mut parts = settings.split(';');
        let period: u32 = parts.next()?.trim().parse().ok()?;
        let digits: u32 = parts.next()?.trim().parse().ok()?;
        checked_params(period, digits)?;

        Some(Self {
            secret,
            period,
            digits,
            algo: TotpAlgo::Sha1,
        })
    }

    /// Compute the code for the time step containing `now_unix` (seconds since
    /// the Unix epoch).
    pub fn compute_at(&self, now_unix: u64) -> TotpCode {
        let raw = match self.algo {
            TotpAlgo::Sha1 => totp_lite::totp_custom::<totp_lite::Sha1>(
                self.period as u64,
                self.digits,
                &self.secret,
                now_unix,
            ),
            TotpAlgo::Sha256 => totp_lite::totp_custom::<totp_lite::Sha256>(
                self.period as u64,
                self.digits,
                &self.secret,
                now_unix,
            ),
            TotpAlgo::Sha512 => totp_lite::totp_custom::<totp_lite::Sha512>(
                self.period as u64,
                self.digits,
                &self.secret,
                now_unix,
            ),
        };
        let elapsed_in_window = now_unix % self.period as u64;
        let valid_for_seconds = (self.period as u64 - elapsed_in_window) as u32;
        TotpCode {
            code: raw,
            valid_for_seconds,
            period_seconds: self.period,
        }
    }

    /// Compute the code for the current wall-clock time. If the clock is before
    /// the Unix epoch (it should not be), the step is treated as 0.
    pub fn compute_now(&self) -> TotpCode {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.compute_at(now)
    }
}

/// Decode a base32 secret using the RFC 4648 alphabet without required padding.
/// This is the encoding both otpauth URIs and the legacy `TOTP Seed` field use.
fn decode_base32_secret(s: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
}

/// Map an otpauth `algorithm` value to [`TotpAlgo`], case-insensitively. An
/// unrecognized value falls back to SHA1, the otpauth default.
fn parse_algo(value: &str) -> TotpAlgo {
    match value.to_uppercase().as_str() {
        "SHA256" => TotpAlgo::Sha256,
        "SHA512" => TotpAlgo::Sha512,
        _ => TotpAlgo::Sha1,
    }
}

/// Turn a "no config found" situation into the typed error the tool surface
/// reports. The Phase 3 caller, after trying both the modern and legacy
/// sources, uses this when an entry has neither.
///
/// This keeps the error idiom in one place rather than re-spelling the
/// `NoOtpConfigured` construction at each call site.
pub fn no_otp_configured() -> CoreError {
    ErrorCode::NoOtpConfigured.into()
}

/// Resolve a [`TotpConfig`] into a code, or report [`ErrorCode::NoOtpConfigured`]
/// when the option is empty. A convenience for callers that already hold an
/// `Option<TotpConfig>` from the parse step.
pub fn code_or_error(config: Option<TotpConfig>, now_unix: u64) -> CoreResult<TotpCode> {
    match config {
        Some(cfg) => Ok(cfg.compute_at(now_unix)),
        None => Err(no_otp_configured()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A well-known RFC-style test secret used across TOTP implementations.
    const SAMPLE_URI: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn parses_minimal_otpauth_uri() {
        let cfg = TotpConfig::parse(SAMPLE_URI).expect("parse");
        assert!(!cfg.secret.is_empty());
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.algo, TotpAlgo::Sha1);
    }

    #[test]
    fn rejects_non_otpauth_and_hotp_and_non_url() {
        // Wrong scheme.
        assert!(TotpConfig::parse("https://example.com/").is_none());
        // Right scheme, wrong type (hotp, not totp).
        assert!(TotpConfig::parse("otpauth://hotp/foo?secret=ABC").is_none());
        // Not a URL at all.
        assert!(TotpConfig::parse("not a url").is_none());
    }

    #[test]
    fn rejects_missing_secret() {
        assert!(TotpConfig::parse("otpauth://totp/Example?period=30").is_none());
    }

    #[test]
    fn parses_custom_period_and_digits() {
        let uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=60&digits=8";
        let cfg = TotpConfig::parse(uri).expect("parse");
        assert_eq!(cfg.period, 60);
        assert_eq!(cfg.digits, 8);
    }

    #[test]
    fn parses_sha256_algorithm() {
        let uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256";
        let cfg = TotpConfig::parse(uri).expect("parse");
        assert_eq!(cfg.algo, TotpAlgo::Sha256);
    }

    #[test]
    fn parses_lowercase_algorithm_name() {
        let uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=sha512";
        let cfg = TotpConfig::parse(uri).expect("parse");
        assert_eq!(cfg.algo, TotpAlgo::Sha512);
    }

    #[test]
    fn compute_at_known_vector() {
        // RFC 6238 style vector: this secret at t=59 yields 287082 for SHA1/6.
        let cfg = TotpConfig::parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .expect("parse");
        let code = cfg.compute_at(59);
        assert_eq!(code.code, "287082");
        assert_eq!(code.period_seconds, 30);
    }

    #[test]
    fn valid_for_seconds_at_window_boundaries() {
        let cfg = TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP").expect("parse");
        // Start of a step: full period remains.
        assert_eq!(cfg.compute_at(0).valid_for_seconds, 30);
        // Last second of the step: one second remains.
        assert_eq!(cfg.compute_at(29).valid_for_seconds, 1);
        // Start of the next step: full period again.
        assert_eq!(cfg.compute_at(30).valid_for_seconds, 30);
    }

    #[test]
    fn period_seconds_echoes_config() {
        let cfg = TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=45")
            .expect("parse");
        let code = cfg.compute_at(0);
        assert_eq!(code.period_seconds, 45);
        assert_eq!(code.valid_for_seconds, 45);
    }

    #[test]
    fn from_legacy_parses_settings_and_computes() {
        // Same secret and parameters as the known vector, expressed as the
        // legacy field pair: base32 seed plus a "period;digits" settings string.
        let cfg = TotpConfig::from_legacy("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "30;6")
            .expect("legacy parse");
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.algo, TotpAlgo::Sha1);
        let code = cfg.compute_at(59);
        assert_eq!(code.code, "287082");
        assert_eq!(code.period_seconds, 30);
    }

    #[test]
    fn from_legacy_tolerates_whitespace_in_settings() {
        let cfg = TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", " 60 ; 8 ").expect("legacy parse");
        assert_eq!(cfg.period, 60);
        assert_eq!(cfg.digits, 8);
    }

    #[test]
    fn from_legacy_rejects_empty_or_malformed() {
        // Empty seed.
        assert!(TotpConfig::from_legacy("", "30;6").is_none());
        // Settings missing the digits part.
        assert!(TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30").is_none());
        // Non-numeric settings.
        assert!(TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "thirty;six").is_none());
    }

    #[test]
    fn parse_rejects_zero_period_without_panic() {
        // period=0 would divide by zero in compute_at and inside totp_lite.
        // The config must be refused rather than built.
        assert!(
            TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0").is_none()
        );
    }

    #[test]
    fn parse_rejects_out_of_range_digits_without_panic() {
        // digits=20 overflows 10^digits in u64 and panics totp_lite's pow.
        assert!(
            TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=20").is_none()
        );
        // digits=0 produces an empty code and is equally malformed.
        assert!(
            TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=0").is_none()
        );
    }

    #[test]
    fn from_legacy_rejects_zero_period_and_bad_digits_without_panic() {
        // Legacy "period;digits" strings carrying the same dangerous values.
        assert!(TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "0;6").is_none());
        assert!(TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;20").is_none());
        assert!(TotpConfig::from_legacy("JBSWY3DPEHPK3PXP", "30;0").is_none());
    }

    #[test]
    fn parse_accepts_digit_bounds() {
        // The accepted edges of the digits range still build a config.
        let one =
            TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=1").expect("one");
        assert_eq!(one.digits, 1);
        let ten = TotpConfig::parse("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=10")
            .expect("ten");
        assert_eq!(ten.digits, 10);
        // And the code computes without panic at both edges.
        let _ = one.compute_at(59);
        let _ = ten.compute_at(59);
    }

    #[test]
    fn code_or_error_reports_no_otp_when_none() {
        let err = code_or_error(None, 59).unwrap_err();
        assert_eq!(err.code(), "NO_OTP_CONFIGURED");
        assert_eq!(err.code_enum(), ErrorCode::NoOtpConfigured);
    }

    #[test]
    fn code_or_error_computes_when_present() {
        let cfg = TotpConfig::parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .expect("parse");
        let code = code_or_error(Some(cfg), 59).expect("code");
        assert_eq!(code.code, "287082");
    }
}
