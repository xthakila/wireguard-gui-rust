//! Public IP discovery (used to show the user their externally-visible IP before/after connect).
//!
//! Strategy:
//!   1. GET https://1.1.1.1/cdn-cgi/trace  — Cloudflare's trace endpoint; parse the `ip=` line.
//!   2. On any failure, fall back to https://api.ipify.org which returns the bare IP as plain text.
//!
//! Both HTTP calls are blocking (`ureq`) and are run on a Tokio blocking thread so the async
//! runtime is never stalled.

use crate::error::{AppError, AppResult};

/// Fetch the current public IP (e.g. via Cloudflare's `cdn-cgi/trace`).
///
/// Tries Cloudflare first; falls back to ipify on any error.
pub async fn fetch_public_ip() -> AppResult<String> {
    tokio::task::spawn_blocking(fetch_public_ip_blocking)
        .await
        .map_err(|join_err| AppError::PublicIpFetchFailed(join_err.to_string()))?
}

/// The real work, suitable for `spawn_blocking`.
fn fetch_public_ip_blocking() -> AppResult<String> {
    // --- Primary: Cloudflare cdn-cgi/trace ---
    if let Ok(body) = ureq::get("https://1.1.1.1/cdn-cgi/trace")
        .call()
        .map(|r| r.into_string())
        && let Ok(body_str) = body
        && let Some(ip) = parse_cf_trace(&body_str)
    {
        return Ok(ip);
    }

    // --- Fallback: ipify ---
    let ip = ureq::get("https://api.ipify.org")
        .call()
        .map_err(|e| AppError::PublicIpFetchFailed(e.to_string()))?
        .into_string()
        .map_err(|e| AppError::PublicIpFetchFailed(e.to_string()))?;

    let ip = ip.trim().to_owned();
    if ip.is_empty() {
        return Err(AppError::PublicIpFetchFailed(
            "ipify returned an empty body".to_owned(),
        ));
    }
    Ok(ip)
}

/// Parse the `ip=` line out of a Cloudflare `cdn-cgi/trace` response body.
///
/// The body is a series of `key=value` lines separated by newlines (no spaces around `=`).
/// Returns `Some(ip_string)` when the `ip` key is present and its value is non-empty,
/// `None` otherwise.
pub fn parse_cf_trace(body: &str) -> Option<String> {
    for line in body.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit tests — pure logic only, no network, no filesystem, no root required.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::parse_cf_trace;

    /// A representative Cloudflare cdn-cgi/trace body (captured from a real response).
    const SAMPLE_TRACE: &str = "\
fl=123abc
h=1.1.1.1
ip=203.0.113.42
ts=1718273400.123
visit_scheme=https
uag=Mozilla/5.0
colo=SIN
sliver=none
http=http/2
loc=IN
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519
";

    #[test]
    fn parses_ip_from_sample_trace() {
        assert_eq!(
            parse_cf_trace(SAMPLE_TRACE),
            Some("203.0.113.42".to_owned())
        );
    }

    #[test]
    fn parses_ipv6_address() {
        let body = "fl=x\nip=2001:db8::1\nts=0\n";
        assert_eq!(parse_cf_trace(body), Some("2001:db8::1".to_owned()));
    }

    #[test]
    fn returns_none_when_ip_line_missing() {
        let body = "fl=abc\nts=1234\nwarp=off\n";
        assert_eq!(parse_cf_trace(body), None);
    }

    #[test]
    fn returns_none_on_empty_body() {
        assert_eq!(parse_cf_trace(""), None);
    }

    #[test]
    fn returns_none_when_ip_value_empty() {
        // Malformed line: ip= with nothing after
        let body = "fl=abc\nip=\nts=1234\n";
        assert_eq!(parse_cf_trace(body), None);
    }

    #[test]
    fn does_not_match_keys_that_only_contain_ip() {
        // "myip=1.2.3.4" must NOT match (strip_prefix("ip=") requires exact prefix)
        let body = "myip=1.2.3.4\nskip=no\n";
        assert_eq!(parse_cf_trace(body), None);
    }

    #[test]
    fn returns_first_ip_line_when_duplicated() {
        // Edge case: two ip= lines — return the first.
        let body = "ip=10.0.0.1\nip=10.0.0.2\n";
        assert_eq!(parse_cf_trace(body), Some("10.0.0.1".to_owned()));
    }

    #[test]
    fn handles_windows_line_endings() {
        // CRLF bodies: strip_prefix works, trim() removes the trailing \r.
        let body = "fl=abc\r\nip=198.51.100.7\r\nts=0\r\n";
        assert_eq!(parse_cf_trace(body), Some("198.51.100.7".to_owned()));
    }

    #[test]
    fn handles_ip_line_with_surrounding_whitespace_only_in_value() {
        // Leading/trailing spaces on the value should be stripped.
        let body = "ip=  1.2.3.4  \nts=0\n";
        assert_eq!(parse_cf_trace(body), Some("1.2.3.4".to_owned()));
    }
}
