//! otpauth URI parsing and TOTP code computation.
//!
//! Two sources feed a [`TotpConfig`]:
//!
//! - the modern `otpauth://totp/...` URI stored in an entry's `otp` field
//!   ([`TotpConfig::parse`]), and
//! - KeePass 2's native `TimeOtp-*` fields, via
//!   [`TotpConfig::from_keepass_native`], and
//! - the legacy KeePass field pair `TOTP Seed` (base32 secret) plus
//!   `TOTP Settings` (a `period;digits` string), via
//!   [`TotpConfig::from_legacy`].
//!
//! [`resolve_for_entry`] picks the source for an entry; every caller goes
//! through it.
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

use crate::engine::secret::Secret;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::error::{CoreError, CoreResult, ErrorCode};

/// A computed one-time code plus its remaining lifetime.
///
/// `code` is the current digits. `valid_for_seconds` counts down to the end of
/// the current time step (it equals `period_seconds` at the start of a step and
/// `1` on the last second). `period_seconds` echoes the step length so a caller
/// can render a progress indicator without re-reading the config.
///
/// The code is a [`Secret`]: it is meant for the agent's response only and
/// must never reach a log, so `Debug` redacts it.
#[derive(Debug, Clone)]
pub struct TotpCode {
    /// The current one-time code, as a string of digits.
    pub code: Secret<String>,
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
/// to compute a code. The secret is a [`Secret`], so `Debug` redacts it.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// The decoded (raw bytes) shared secret.
    pub secret: Secret<Vec<u8>>,
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
            secret: Secret::new(secret?),
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
            secret: Secret::new(secret),
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
                self.secret.expose(),
                now_unix,
            ),
            TotpAlgo::Sha256 => totp_lite::totp_custom::<totp_lite::Sha256>(
                self.period as u64,
                self.digits,
                self.secret.expose(),
                now_unix,
            ),
            TotpAlgo::Sha512 => totp_lite::totp_custom::<totp_lite::Sha512>(
                self.period as u64,
                self.digits,
                self.secret.expose(),
                now_unix,
            ),
        };
        let elapsed_in_window = now_unix % self.period as u64;
        let valid_for_seconds = (self.period as u64 - elapsed_in_window) as u32;
        TotpCode {
            code: Secret::new(raw),
            valid_for_seconds,
            period_seconds: self.period,
        }
    }

    /// The time (Unix seconds) a code is computed at for a request that asked
    /// for `requested` (None means now), given the current time `now`.
    ///
    /// The request is clamped to `now` plus or minus one period. That still
    /// lets a caller get the previous or next code (clock skew between this
    /// host and the verifier), but never a code for a far-past or far-future
    /// step: an agent able to ask for any time could harvest tomorrow's codes
    /// today, which defeats the "only the current code crosses out" rule.
    pub fn evaluation_time(&self, requested: Option<u64>, now: u64) -> u64 {
        let period = u64::from(self.period);
        let earliest = now.saturating_sub(period);
        let latest = now.saturating_add(period);
        requested.unwrap_or(now).clamp(earliest, latest)
    }

    /// Compute the code for the current wall-clock time. If the clock is before
    /// the Unix epoch (it should not be), the step is treated as 0.
    pub fn compute_now(&self) -> TotpCode {
        self.compute_at(unix_now())
    }
}

/// The current wall-clock time in Unix seconds. A clock before the epoch (it
/// should not be) reads as 0.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode a base32 secret (RFC 4648 alphabet). The input is normalized first:
/// whitespace is removed, letters are uppercased, and trailing `=` padding is
/// dropped. Real secrets arrive lowercase, grouped in blocks of four, or
/// padded (authenticator setup pages, KeePass's entry dialog), and the strict
/// decoder rejected all three. This is the encoding both otpauth URIs and the
/// legacy `TOTP Seed` field use, and KeePass's `TimeOtp-Secret-Base32`.
fn decode_base32_secret(s: &str) -> Option<Vec<u8>> {
    let normalized: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        normalized.trim_end_matches('='),
    )
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

/// The entry field names the TOTP sources are read from. One place, so the
/// resolver and its tests agree on the spelling.
pub mod field_names {
    /// KeePassXC's modern field: an `otpauth://totp/...` URI.
    pub use keepass::db::fields::OTP;
    /// KeeOtp / older KeePassXC: base32 seed plus a `period;digits` string.
    pub const LEGACY_SEED: &str = "TOTP Seed";
    /// See [`LEGACY_SEED`].
    pub const LEGACY_SETTINGS: &str = "TOTP Settings";
    /// KeePass 2 native (2.47+, the `{TIMEOTP}` placeholder): the secret, as
    /// UTF-8 text.
    pub const NATIVE_SECRET: &str = "TimeOtp-Secret";
    /// KeePass 2 native: the secret, hex-encoded.
    pub const NATIVE_SECRET_HEX: &str = "TimeOtp-Secret-Hex";
    /// KeePass 2 native: the secret, base32-encoded.
    pub const NATIVE_SECRET_BASE32: &str = "TimeOtp-Secret-Base32";
    /// KeePass 2 native: the secret, base64-encoded.
    pub const NATIVE_SECRET_BASE64: &str = "TimeOtp-Secret-Base64";
    /// KeePass 2 native: code length (default 6, at most 8).
    pub const NATIVE_LENGTH: &str = "TimeOtp-Length";
    /// KeePass 2 native: time step in seconds (default 30).
    pub const NATIVE_PERIOD: &str = "TimeOtp-Period";
    /// KeePass 2 native: `HMAC-SHA-1` (default), `HMAC-SHA-256`, or
    /// `HMAC-SHA-512`.
    pub const NATIVE_ALGORITHM: &str = "TimeOtp-Algorithm";
}

/// The longest code KeePass's native TOTP produces (its documented maximum).
const NATIVE_MAX_DIGITS: u32 = 8;

/// Resolve the [`TotpConfig`] an entry carries, trying its sources in order:
///
/// 1. the modern `otp` field (an otpauth URI, KeePassXC);
/// 2. the KeePass 2 native `TimeOtp-*` fields (keepass.info, "Placeholders",
///    the `{TIMEOTP}` section);
/// 3. the legacy `TOTP Seed` + `TOTP Settings` pair.
///
/// A source that is present but malformed falls through to the next. Returns
/// `None` when no source yields a usable config.
///
/// This is the single source of truth for "does this entry have usable TOTP":
/// `kdbx_get_otp` computes with it, and the read views and the stage diff set
/// `has_otp` from it, so the advertised capability and the behavior agree.
pub fn resolve_for_entry(entry: &keepass::db::Entry) -> Option<TotpConfig> {
    use field_names::*;
    if let Some(config) = entry.get(OTP).and_then(TotpConfig::parse) {
        return Some(config);
    }
    if let Some(config) = TotpConfig::from_keepass_native(|name| entry.get(name)) {
        return Some(config);
    }
    match (entry.get(LEGACY_SEED), entry.get(LEGACY_SETTINGS)) {
        (Some(seed), Some(settings)) => TotpConfig::from_legacy(seed, settings),
        _ => None,
    }
}

impl TotpConfig {
    /// Build a config from KeePass 2's native `TimeOtp-*` fields, read through
    /// `get`. Exactly one of the four secret fields must be present and
    /// non-empty (KeePass's rule; an empty one is skipped); `TimeOtp-Length` (1..=8, default 6), `TimeOtp-Period` (default
    /// 30), and `TimeOtp-Algorithm` (default `HMAC-SHA-1`) are optional. Any
    /// malformed or unknown value yields `None`.
    pub fn from_keepass_native<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Option<Self> {
        use base64::Engine;
        use field_names::*;
        let decoders: [(&str, SecretDecoder); 4] = [
            (NATIVE_SECRET, |v| Some(v.as_bytes().to_vec())),
            (NATIVE_SECRET_HEX, decode_hex),
            (NATIVE_SECRET_BASE32, decode_base32_secret),
            (NATIVE_SECRET_BASE64, |v| {
                let compact: String = v.chars().filter(|c| !c.is_whitespace()).collect();
                base64::engine::general_purpose::STANDARD
                    .decode(compact)
                    .ok()
            }),
        ];
        // An empty secret field does not count (KeePass skips it).
        let mut present = decoders.iter().filter_map(|(name, decode)| {
            get(name)
                .filter(|value| !value.is_empty())
                .map(|value| (*decode, value))
        });
        let (decode, value) = present.next()?;
        if present.next().is_some() {
            return None;
        }
        let secret = decode(value).filter(|s| !s.is_empty())?;

        let digits = match get(NATIVE_LENGTH) {
            Some(v) => v.trim().parse().ok().filter(|d| *d <= NATIVE_MAX_DIGITS)?,
            None => 6,
        };
        let period = match get(NATIVE_PERIOD) {
            Some(v) => v.trim().parse().ok()?,
            None => 30,
        };
        let algo = match get(NATIVE_ALGORITHM).map(str::trim) {
            None | Some("HMAC-SHA-1") => TotpAlgo::Sha1,
            Some("HMAC-SHA-256") => TotpAlgo::Sha256,
            Some("HMAC-SHA-512") => TotpAlgo::Sha512,
            Some(_) => return None,
        };
        checked_params(period, digits)?;
        Some(Self {
            secret: Secret::new(secret),
            period,
            digits,
            algo,
        })
    }
}

/// Decodes one encoding of a KeePass native TOTP secret field.
type SecretDecoder = fn(&str) -> Option<Vec<u8>>;

/// Decode a hex string (whitespace ignored, either case) to bytes.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_digit(16).map(|d| d as u8))
        .collect::<Option<_>>()?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    Some(digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
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
        assert!(!cfg.secret.expose().is_empty());
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.algo, TotpAlgo::Sha1);
    }

    #[test]
    fn evaluation_time_is_clamped_to_one_period_around_now() {
        let cfg = TotpConfig::parse(SAMPLE_URI).expect("parse");
        let now = 2_000_000_000u64;
        // Inside the window: used as asked.
        assert_eq!(cfg.evaluation_time(Some(now - 30), now), now - 30);
        assert_eq!(cfg.evaluation_time(Some(now + 30), now), now + 30);
        assert_eq!(cfg.evaluation_time(None, now), now);
        // Outside it: pulled to the nearest edge, so no far-past or far-future
        // code can be harvested.
        assert_eq!(cfg.evaluation_time(Some(0), now), now - 30);
        assert_eq!(cfg.evaluation_time(Some(u64::MAX), now), now + 30);
        // Near the epoch the lower edge saturates at zero.
        assert_eq!(cfg.evaluation_time(Some(0), 10), 0);
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
        assert_eq!(code.code.expose(), "287082");
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
        assert_eq!(code.code.expose(), "287082");
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
        assert_eq!(code.code.expose(), "287082");
    }

    /// Build a database holding one root entry with the given unprotected
    /// fields, and resolve its TOTP config.
    fn resolve_fields(fields_spec: &[(&str, &str)]) -> Option<TotpConfig> {
        let mut db = keepass::Database::new();
        db.root_mut().add_entry().edit(|e| {
            for (name, value) in fields_spec {
                e.set_unprotected(*name, *value);
            }
        });
        let entry = db.iter_all_entries().next().expect("one entry");
        resolve_for_entry(&entry)
    }

    /// RFC 6238 SHA-1 secret "12345678901234567890" at t=59 -> 94287082;
    /// six digits -> 287082.
    const RFC_SHA1_AT_59: &str = "287082";

    #[test]
    fn resolve_for_entry_prefers_otpauth_then_native_then_legacy() {
        let modern = ("otp", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP");
        let legacy = [("TOTP Seed", "JBSWY3DPEHPK3PXP"), ("TOTP Settings", "30;6")];
        assert!(resolve_fields(&[modern]).is_some());
        assert!(resolve_fields(&legacy).is_some());
        // Seed without settings does not resolve.
        assert!(resolve_fields(&legacy[..1]).is_none());
        assert!(resolve_fields(&[]).is_none());
        // A malformed modern field falls through to the next source.
        let mut fallthrough = vec![("otp", "not-an-otpauth-uri")];
        fallthrough.extend_from_slice(&legacy);
        assert!(resolve_fields(&fallthrough).is_some());
        // The KeePass 2 native fields outrank the legacy pair.
        let both = [
            ("TimeOtp-Secret", "12345678901234567890"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;8"),
        ];
        let cfg = resolve_fields(&both).expect("native resolves");
        assert_eq!(cfg.compute_at(59).code.expose(), RFC_SHA1_AT_59);
    }

    #[test]
    fn keepass_native_secret_encodings_all_decode_to_the_same_key() {
        for (field, value) in [
            ("TimeOtp-Secret", "12345678901234567890"),
            (
                "TimeOtp-Secret-Hex",
                "3132333435363738393031323334353637383930",
            ),
            ("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            ("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="),
        ] {
            let cfg = resolve_fields(&[(field, value)]).unwrap_or_else(|| panic!("{field}"));
            assert_eq!(cfg.period, 30, "{field} default period");
            assert_eq!(cfg.digits, 6, "{field} default length");
            assert_eq!(cfg.compute_at(59).code.expose(), RFC_SHA1_AT_59, "{field}");
        }
    }

    #[test]
    fn empty_native_secret_fields_are_ignored_when_counting() {
        // KeePass skips empty TimeOtp-Secret* fields, so an entry carrying an
        // empty plain secret alongside a real base32 one has exactly one
        // secret. And an entry whose only secret field is empty has none.
        let cfg = resolve_fields(&[
            ("TimeOtp-Secret", ""),
            ("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ])
        .expect("the non-empty secret is used");
        assert_eq!(cfg.compute_at(59).code.expose(), RFC_SHA1_AT_59);
        assert!(resolve_fields(&[("TimeOtp-Secret-Hex", "")]).is_none());
    }

    #[test]
    fn keepass_native_length_period_and_algorithm() {
        // RFC 6238 SHA-256 vector: 32-byte secret, t=59, 8 digits -> 46119246.
        let cfg = resolve_fields(&[
            ("TimeOtp-Secret", "12345678901234567890123456789012"),
            ("TimeOtp-Length", "8"),
            ("TimeOtp-Period", "30"),
            ("TimeOtp-Algorithm", "HMAC-SHA-256"),
        ])
        .expect("resolves");
        assert_eq!(cfg.algo, TotpAlgo::Sha256);
        assert_eq!(cfg.compute_at(59).code.expose(), "46119246");
        // KeePass caps the length at 8; a longer one, an unknown algorithm, or
        // two secret fields at once is not a usable config.
        assert!(resolve_fields(&[("TimeOtp-Secret", "x"), ("TimeOtp-Length", "9")]).is_none());
        assert!(resolve_fields(&[("TimeOtp-Secret", "x"), ("TimeOtp-Algorithm", "MD5")]).is_none());
        assert!(resolve_fields(&[("TimeOtp-Secret", "x"), ("TimeOtp-Secret-Hex", "78")]).is_none());
    }

    #[test]
    fn base32_secrets_are_normalized_before_decoding() {
        // Lowercase, grouped with spaces, and padded: all common in the wild
        // (authenticator setup pages, KeePass's own entry dialog).
        let canonical = decode_base32_secret("JBSWY3DPEHPK3PXP").expect("canonical");
        for messy in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSWY3DPEHPK3PXP====",
            " jbsw\ty3dp ehpk3pxp\n",
        ] {
            assert_eq!(
                decode_base32_secret(messy).as_ref(),
                Some(&canonical),
                "{messy:?}"
            );
        }
        let cfg =
            TotpConfig::parse("otpauth://totp/X?secret=jbswy3dpehpk3pxp").expect("lowercase uri");
        assert_eq!(cfg.secret.expose(), &canonical);
    }
}
