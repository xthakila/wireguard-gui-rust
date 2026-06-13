//! Status / connection summary view.
//!
//! `status_bar` renders the full connection status panel:
//!   - App header (name + version)
//!   - Large connection indicator with colour driven by `TunnelStatus`
//!   - Live stats (last-handshake age, rx/tx, endpoint) when Connected
//!   - Public-IP display when available
//!   - Disconnect button (only when Connected)
//!   - Navigation row: New | Import | Settings

use std::time::SystemTime;

use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Color, Element, Length, Padding};

use crate::app::{Message, State, TunnelStatus};

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette (hex → iced::Color)
// ─────────────────────────────────────────────────────────────────────────────

const GREEN: Color = Color {
    r: 0.133,
    g: 0.773,
    b: 0.369,
    a: 1.0,
};
const YELLOW: Color = Color {
    r: 0.957,
    g: 0.761,
    b: 0.051,
    a: 1.0,
};
const RED: Color = Color {
    r: 0.937,
    g: 0.267,
    b: 0.267,
    a: 1.0,
};
const GREY: Color = Color {
    r: 0.557,
    g: 0.557,
    b: 0.557,
    a: 1.0,
};
const WHITE: Color = Color {
    r: 1.0,
    g: 1.0,
    b: 1.0,
    a: 1.0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the live connection / status summary panel.
pub fn status_bar(state: &State) -> Element<'_, Message> {
    let content = column![
        app_header(),
        iced::widget::rule::horizontal(1),
        connection_indicator(state),
        live_stats_section(state),
        iced::widget::rule::horizontal(1),
        nav_row(),
    ]
    .spacing(12)
    .padding(Padding::from([16, 20]));

    container(content)
        .width(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// App header: icon text + version
// ─────────────────────────────────────────────────────────────────────────────

fn app_header<'a>() -> Element<'a, Message> {
    let name = text("WireGuard")
        .size(22)
        .color(WHITE);

    let version = text(concat!("v", env!("CARGO_PKG_VERSION")))
        .size(13)
        .color(GREY);

    // Shield icon rendered as styled text — no external asset dependency.
    let icon = text("🛡")
        .size(26);

    row![icon, name, version]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection indicator + disconnect button
// ─────────────────────────────────────────────────────────────────────────────

fn connection_indicator(state: &State) -> Element<'_, Message> {
    let (dot_color, label, sub_label): (Color, &str, Option<String>) =
        match &state.tunnel_status {
            TunnelStatus::Connected(name) => (
                GREEN,
                "Connected",
                Some(name.clone()),
            ),
            TunnelStatus::Connecting(name) => (
                YELLOW,
                "Connecting…",
                Some(name.clone()),
            ),
            TunnelStatus::Disconnecting => (
                YELLOW,
                "Disconnecting…",
                None,
            ),
            TunnelStatus::Error(msg) => (
                RED,
                "Error",
                Some(msg.clone()),
            ),
            TunnelStatus::Disconnected => (
                GREY,
                "Disconnected",
                None,
            ),
        };

    let is_connected = matches!(state.tunnel_status, TunnelStatus::Connected(_));

    // Large coloured dot.
    let dot = container(text(" "))
        .width(Length::Fixed(14.0))
        .height(Length::Fixed(14.0))
        .style(move |_theme| {
            container::Style {
                background: Some(iced::Background::Color(dot_color)),
                border: iced::Border {
                    radius: iced::border::Radius::from(7.0),
                    ..Default::default()
                },
                ..Default::default()
            }
        });

    let status_label = text(label)
        .size(28)
        .color(dot_color);

    let mut indicator_col = column![
        row![dot, status_label]
            .spacing(10)
            .align_y(Alignment::Center),
    ]
    .spacing(4);

    if let Some(sub) = sub_label {
        let sub_text = text(sub).size(14).color(GREY);
        indicator_col = indicator_col.push(sub_text);
    }

    // Public IP row (shown whenever it is known).
    if let Some(ip) = &state.public_ip {
        let ip_label = text(format!("Public IP: {ip}")).size(13).color(GREY);
        indicator_col = indicator_col.push(ip_label);
    } else if state.public_ip_loading {
        indicator_col = indicator_col.push(
            text("Fetching public IP…").size(13).color(GREY),
        );
    }

    // Disconnect button — only enabled while Connected.
    let disconnect_btn = if is_connected {
        button(text("Disconnect").size(14))
            .on_press(Message::DisconnectCurrent)
            .style(button::danger)
    } else {
        // Visually disabled — no on_press means iced renders it greyed automatically.
        button(text("Disconnect").size(14))
            .style(button::danger)
    };

    row![
        indicator_col.width(Length::Fill),
        disconnect_btn,
    ]
    .spacing(16)
    .align_y(Alignment::Center)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Live stats (handshake age, rx/tx, endpoint) — only while Connected
// ─────────────────────────────────────────────────────────────────────────────

fn live_stats_section(state: &State) -> Element<'_, Message> {
    // Only render while there is live status data to show.
    let Some(live) = &state.live_status else {
        return iced::widget::Space::new().into();
    };

    // Aggregate across all peers for totals.
    let total_rx: u64 = live.peers.iter().map(|p| p.rx_bytes).sum();
    let total_tx: u64 = live.peers.iter().map(|p| p.tx_bytes).sum();

    // Last handshake: take the most-recently-seen peer.
    let latest_handshake = live
        .peers
        .iter()
        .filter_map(|p| p.last_handshake)
        .max();

    let mut stats_col = column![].spacing(6);

    // Handshake age.
    let handshake_str = match latest_handshake {
        Some(hs) => {
            let age_secs = SystemTime::now()
                .duration_since(hs)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("Last handshake: {}", format_duration(age_secs))
        }
        None => "Last handshake: never".to_owned(),
    };
    stats_col = stats_col.push(stat_row("", handshake_str));

    // rx / tx transfer.
    stats_col = stats_col.push(stat_row(
        "",
        format!(
            "Transfer: {} received  /  {} sent",
            format_bytes(total_rx),
            format_bytes(total_tx)
        ),
    ));

    // Endpoint (first peer with a known endpoint).
    if let Some(endpoint) = live.peers.iter().find_map(|p| p.endpoint.as_deref()) {
        stats_col = stats_col.push(stat_row("", format!("Endpoint: {endpoint}")));
    }

    container(stats_col)
        .padding(Padding::from([8, 12]))
        .style(|theme: &iced::Theme| {
            let palette = theme.palette();
            container::Style {
                background: Some(iced::Background::Color(Color {
                    r: palette.background.r * 0.85,
                    g: palette.background.g * 0.85,
                    b: palette.background.b * 0.85,
                    a: 1.0,
                })),
                border: iced::Border {
                    radius: iced::border::Radius::from(6.0),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .width(Length::Fill)
        .into()
}

/// A small labelled stat row (icon glyph + text, monospaced feel).
///
/// Takes owned strings so the returned element borrows nothing from the caller's
/// locals (the fragments are moved into the `text` widgets).
fn stat_row(icon: impl Into<String>, label: impl Into<String>) -> Element<'static, Message> {
    let icon_w = text(icon.into()).size(13).color(GREY);
    let label_w = text(label.into()).size(13).color(GREY);
    row![icon_w, label_w].spacing(6).align_y(Alignment::Center).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation row: New | Import | Settings
// ─────────────────────────────────────────────────────────────────────────────

fn nav_row<'a>() -> Element<'a, Message> {
    let new_btn = button(text("+ New").size(13))
        .on_press(Message::OpenNewProfile);

    let import_btn = button(text("Import").size(13))
        .on_press(Message::ImportProfile);

    let settings_btn = button(text("Settings").size(13))
        .on_press(Message::OpenSettings);

    row![new_btn, import_btn, settings_btn]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers (pure, no I/O)
// ─────────────────────────────────────────────────────────────────────────────

/// Format a duration in seconds as a human-readable string ("2 minutes ago", etc.).
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} second{} ago", if secs == 1 { "" } else { "s" })
    } else if secs < 3600 {
        let m = secs / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else if secs < 86400 {
        let h = secs / 3600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let d = secs / 86400;
        format!("{d} day{} ago", if d == 1 { "" } else { "s" })
    }
}

/// Format a byte count as KiB / MiB / GiB with one decimal place.
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (pure; no GUI, no runtime required)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_under_kib() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 2), "2.0 MiB");
    }

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(0), "0 seconds ago");
        assert_eq!(format_duration(1), "1 second ago");
        assert_eq!(format_duration(45), "45 seconds ago");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(60), "1 minute ago");
        assert_eq!(format_duration(120), "2 minutes ago");
        assert_eq!(format_duration(3599), "59 minutes ago");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3600), "1 hour ago");
        assert_eq!(format_duration(7200), "2 hours ago");
    }

    #[test]
    fn format_duration_days() {
        assert_eq!(format_duration(86400), "1 day ago");
        assert_eq!(format_duration(86400 * 3), "3 days ago");
    }
}
