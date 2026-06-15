//! Desktop notifications (feature 1).
//!
//! Thin, fire-and-forget wrappers over [`notify_rust`]. Every call is
//! non-blocking and swallows errors: a missing notification daemon (e.g. in a
//! headless CI box) must never sink a connect/disconnect. The reducer decides
//! *whether* to notify (gated on [`crate::settings::AppSettings::notifications_enabled`]);
//! this module only decides *how*.
//!
//! The summary/body wording is centralised in the `notify_*` helpers so the tray
//! and the dashboard stay consistent.

// ─────────────────────────────────────────────────────────────────────────────
// Pure formatting helpers (no I/O — unit-testable without a notification daemon)
// ─────────────────────────────────────────────────────────────────────────────

/// Return the `(summary, body)` text for a connect notification.
///
/// Extracted from `notify_connected` so tests can verify the wording without
/// touching a real notification daemon.
pub fn fmt_connected(name: &str) -> (String, String) {
    ("WireGuard connected".to_owned(), format!("Connected to {name}"))
}

/// Return the `(summary, body)` text for a user-initiated disconnect notification.
pub fn fmt_disconnected(name: &str) -> (String, String) {
    (
        "WireGuard disconnected".to_owned(),
        format!("Disconnected from {name}"),
    )
}

/// Return the `(summary, body)` text for an unexpected tunnel-drop notification.
pub fn fmt_dropped(name: &str) -> (String, String) {
    (
        "WireGuard tunnel dropped".to_owned(),
        format!("Lost connection to {name}"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Fire-and-forget notification dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Post a desktop notification with the given `summary` and `body`.
///
/// Best-effort: a failure to reach the notification daemon is ignored (the show
/// call's `Result` is dropped). Returns immediately; the platform backend owns
/// any async delivery.
pub fn notify(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname("WireGuard GUI")
        .icon("network-vpn")
        .summary(summary)
        .body(body)
        .show();
}

/// Notify that the tunnel for `name` came up.
pub fn notify_connected(name: &str) {
    let (summary, body) = fmt_connected(name);
    notify(&summary, &body);
}

/// Notify that the tunnel for `name` was disconnected (user-initiated).
pub fn notify_disconnected(name: &str) {
    let (summary, body) = fmt_disconnected(name);
    notify(&summary, &body);
}

/// Notify that the tunnel for `name` dropped unexpectedly (watchdog / handshake stall).
pub fn notify_dropped(name: &str) {
    let (summary, body) = fmt_dropped(name);
    notify(&summary, &body);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── fmt_connected ────────────────────────────────────────────────────────

    #[test]
    fn connected_summary_is_fixed() {
        let (summary, _body) = fmt_connected("home-vpn");
        assert_eq!(summary, "WireGuard connected");
    }

    #[test]
    fn connected_body_contains_name() {
        let (_summary, body) = fmt_connected("home-vpn");
        assert!(body.contains("home-vpn"), "body={body:?}");
    }

    #[test]
    fn connected_body_exact() {
        let (_summary, body) = fmt_connected("home-vpn");
        assert_eq!(body, "Connected to home-vpn");
    }

    #[test]
    fn connected_body_uses_provided_name() {
        // Profile names may contain spaces, hyphens, or unicode.
        let (_summary, body) = fmt_connected("Work VPN — EU");
        assert_eq!(body, "Connected to Work VPN — EU");
    }

    // ── fmt_disconnected ─────────────────────────────────────────────────────

    #[test]
    fn disconnected_summary_is_fixed() {
        let (summary, _body) = fmt_disconnected("home-vpn");
        assert_eq!(summary, "WireGuard disconnected");
    }

    #[test]
    fn disconnected_body_contains_name() {
        let (_summary, body) = fmt_disconnected("home-vpn");
        assert!(body.contains("home-vpn"), "body={body:?}");
    }

    #[test]
    fn disconnected_body_exact() {
        let (_summary, body) = fmt_disconnected("home-vpn");
        assert_eq!(body, "Disconnected from home-vpn");
    }

    // ── fmt_dropped ──────────────────────────────────────────────────────────

    #[test]
    fn dropped_summary_is_fixed() {
        let (summary, _body) = fmt_dropped("home-vpn");
        assert_eq!(summary, "WireGuard tunnel dropped");
    }

    #[test]
    fn dropped_body_contains_name() {
        let (_summary, body) = fmt_dropped("home-vpn");
        assert!(body.contains("home-vpn"), "body={body:?}");
    }

    #[test]
    fn dropped_body_exact() {
        let (_summary, body) = fmt_dropped("home-vpn");
        assert_eq!(body, "Lost connection to home-vpn");
    }

    // ── each function returns distinct summaries ──────────────────────────────

    #[test]
    fn summaries_are_distinct() {
        let (s_conn, _) = fmt_connected("x");
        let (s_disc, _) = fmt_disconnected("x");
        let (s_drop, _) = fmt_dropped("x");
        assert_ne!(s_conn, s_disc);
        assert_ne!(s_conn, s_drop);
        assert_ne!(s_disc, s_drop);
    }

    // ── empty name edge case ─────────────────────────────────────────────────

    #[test]
    fn empty_name_connected() {
        let (_s, body) = fmt_connected("");
        assert_eq!(body, "Connected to ");
    }

    #[test]
    fn empty_name_disconnected() {
        let (_s, body) = fmt_disconnected("");
        assert_eq!(body, "Disconnected from ");
    }

    #[test]
    fn empty_name_dropped() {
        let (_s, body) = fmt_dropped("");
        assert_eq!(body, "Lost connection to ");
    }

    // ── show path (requires a running notification daemon; skipped in CI) ─────

    /// Smoke-test that the builder chain does not panic even when `.show()` would
    /// succeed. Marked `#[ignore]` because it requires a DBus notification daemon
    /// to be running and has real side effects (fires a desktop notification).
    #[test]
    #[ignore]
    fn notify_connected_does_not_panic() {
        notify_connected("test-profile");
    }

    #[test]
    #[ignore]
    fn notify_disconnected_does_not_panic() {
        notify_disconnected("test-profile");
    }

    #[test]
    #[ignore]
    fn notify_dropped_does_not_panic() {
        notify_dropped("test-profile");
    }
}
