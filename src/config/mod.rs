//! Profile configuration: validated names, parsing, key generation, on-disk store.

pub mod keygen;
pub mod profile;
pub mod qr_import;
pub mod store;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// A validated WireGuard profile / interface name.
///
/// Rules (mirrors `wg-quick` / Linux interface-name constraints):
///   - non-empty
///   - at most 15 characters
///   - every char in `[A-Za-z0-9_.=-]`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfileName(String);

impl ProfileName {
    /// Validate and construct a `ProfileName`.
    pub fn new(name: &str) -> AppResult<Self> {
        if name.is_empty() {
            return Err(AppError::InvalidProfileName(
                "name must not be empty".into(),
            ));
        }
        if name.chars().count() > 15 {
            return Err(AppError::InvalidProfileName(
                "name must be at most 15 characters".into(),
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '=' | '-'))
        {
            return Err(AppError::InvalidProfileName(format!(
                "name '{name}' contains characters outside [A-Za-z0-9_.=-]"
            )));
        }
        Ok(ProfileName(name.to_owned()))
    }

    /// Borrow the validated name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ProfileName {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProfileName::new(s)
    }
}

impl TryFrom<String> for ProfileName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ProfileName::new(&value)
    }
}

impl From<ProfileName> for String {
    fn from(value: ProfileName) -> Self {
        value.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── valid names ───────────────────────────────────────────────────────────

    #[test]
    fn valid_simple_name() {
        assert!(ProfileName::new("wg0").is_ok());
    }

    #[test]
    fn valid_name_with_all_allowed_chars() {
        assert!(ProfileName::new("wg0_.=-A").is_ok());
    }

    #[test]
    fn valid_name_exactly_15_chars() {
        assert!(ProfileName::new("abcdefghijklmno").is_ok()); // 15 chars
    }

    #[test]
    fn valid_name_single_char() {
        assert!(ProfileName::new("w").is_ok());
    }

    // ── invalid names ─────────────────────────────────────────────────────────

    #[test]
    fn empty_name_rejected() {
        let err = ProfileName::new("").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn name_too_long_rejected() {
        // 16 characters — one over the 15-char limit
        let err = ProfileName::new("abcdefghijklmnop").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn name_with_space_rejected() {
        let err = ProfileName::new("wg 0").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn name_with_slash_rejected() {
        let err = ProfileName::new("wg/0").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn name_with_at_sign_rejected() {
        let err = ProfileName::new("wg@home").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn name_with_unicode_rejected() {
        let err = ProfileName::new("wg\u{00e9}0").unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    // ── as_str / Display / FromStr round-trips ────────────────────────────────

    #[test]
    fn as_str_returns_inner_value() {
        let n = ProfileName::new("myvpn").unwrap();
        assert_eq!(n.as_str(), "myvpn");
    }

    #[test]
    fn display_matches_inner_value() {
        let n = ProfileName::new("myvpn").unwrap();
        assert_eq!(n.to_string(), "myvpn");
    }

    #[test]
    fn from_str_valid() {
        let n: ProfileName = "wg0".parse().unwrap();
        assert_eq!(n.as_str(), "wg0");
    }

    #[test]
    fn from_str_invalid() {
        let err = "wg/0".parse::<ProfileName>().unwrap_err();
        assert!(matches!(err, AppError::InvalidProfileName(_)));
    }

    #[test]
    fn try_from_string_valid() {
        let n = ProfileName::try_from("wg0".to_owned()).unwrap();
        assert_eq!(n.as_str(), "wg0");
    }

    #[test]
    fn into_string_round_trip() {
        let n = ProfileName::new("wg0").unwrap();
        let s: String = n.into();
        assert_eq!(s, "wg0");
    }
}
