//! Status / connection dashboard — the polished top panel rendered above every
//! screen.
//!
//! Layout (top to bottom):
//!
//! 1. App header row: shield icon + "WireGuard" title + version badge.
//! 2. Connection hero card: a [`status_pill`] (Connected / Connecting /
//!    Disconnecting / Error / Idle), the active profile name as the card title,
//!    and a primary action button ("⏻ Connect" in primary style or "✕
//!    Disconnect" in danger style) — icon-labelled so the toolbar is never bare
//!    text.
//! 3. Stats row (only while Connected AND `live_status` is present): tiles for
//!    Endpoint, Duration, ↓ Received, ↑ Sent, Last Handshake, and Public IP. The
//!    transfer tile embeds a mini bar-sparkline drawn from
//!    [`State::throughput_history`] using container widgets (no canvas feature
//!    required).
//! 4. Toolbar: icon buttons (New | Import | Server | Settings).
//!
//! Every colour, spacing, radius, card surface, pill, and button style is
//! sourced from [`crate::ui::theme`] — never hard-coded here.

use std::time::SystemTime;

use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Background, Color, Element, Length, Padding};

use crate::app::{Message, State, TunnelStatus};
use crate::ui::theme::{self, StatusKind};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the connection dashboard panel.
///
/// Called from the profile-list view (and other screens that show the status
/// bar at the top). Reads [`State`] fields; never mutates state.
pub fn status_bar(state: &State) -> Element<'_, Message> {
    let content = column![
        app_header(),
        hero_card(state),
        stats_section(state),
        toolbar(),
    ]
    .spacing(theme::SPACE_MD)
    .padding(Padding::from([theme::SPACE_LG, theme::SPACE_XL]));

    container(content)
        .width(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// App header
// ─────────────────────────────────────────────────────────────────────────────

fn app_header<'a>() -> Element<'a, Message> {
    let shield = theme::icon(theme::icons::SHIELD);
    let name = theme::title("WireGuard");
    let ver = theme::muted(concat!("v", env!("CARGO_PKG_VERSION")));

    row![shield, name, ver]
        .spacing(theme::SPACE_SM)
        .align_y(Alignment::Center)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Hero connection card
// ─────────────────────────────────────────────────────────────────────────────

fn hero_card(state: &State) -> Element<'_, Message> {
    let (kind, status_label, profile_name) = tunnel_kind(state);

    // Large status pill.
    let pill = theme::status_pill(status_label, kind);

    // Profile name — shown when there is an active profile.
    let name_row: Element<'_, Message> = if let Some(name) = profile_name {
        theme::section_title(name).into()
    } else {
        theme::muted("No profile selected").into()
    };

    // Primary action: Connect or Disconnect depending on state.
    let action_btn = action_button(state);

    let hero_inner = row![
        column![pill, name_row]
            .spacing(theme::SPACE_SM)
            .width(Length::Fill),
        action_btn,
    ]
    .spacing(theme::SPACE_MD)
    .align_y(Alignment::Center);

    container(hero_inner)
        .padding(theme::CARD_PADDING)
        .style(theme::card_style)
        .width(Length::Fill)
        .into()
}

/// Derive the [`StatusKind`], a display label, and the active profile name
/// from the current [`TunnelStatus`].
fn tunnel_kind(state: &State) -> (StatusKind, &'static str, Option<String>) {
    match &state.tunnel_status {
        TunnelStatus::Connected(name) => (StatusKind::Connected, "Connected", Some(name.clone())),
        TunnelStatus::Connecting(name) => {
            (StatusKind::Connecting, "Connecting\u{2026}", Some(name.clone()))
        }
        TunnelStatus::Disconnecting => (StatusKind::Connecting, "Disconnecting\u{2026}", None),
        TunnelStatus::Error(msg) => (StatusKind::Error, "Error", Some(msg.clone())),
        TunnelStatus::Disconnected => (StatusKind::Idle, "Disconnected", None),
    }
}

/// The primary CTA button.  When connected: "✕ Disconnect" in danger style.
/// When disconnecting or connecting: show a disabled ghost button.
/// When disconnected with an active profile: "⏻ Connect" in primary style.
/// Otherwise: a disabled "⏻ Connect" placeholder.
fn action_button(state: &State) -> Element<'_, Message> {
    match &state.tunnel_status {
        TunnelStatus::Connected(_) => {
            let label = row![
                theme::icon(theme::icons::STOP),
                text("Disconnect").size(theme::TEXT_BODY),
            ]
            .spacing(theme::SPACE_XS)
            .align_y(Alignment::Center);

            button(label)
                .on_press(Message::DisconnectCurrent)
                .style(theme::danger())
                .padding([theme::SPACE_SM, theme::SPACE_MD])
                .into()
        }
        TunnelStatus::Connecting(_) | TunnelStatus::Disconnecting => {
            // In-flight — show a disabled ghost button so the layout does not jump.
            let label = row![
                theme::icon(theme::icons::POWER),
                text("Connect").size(theme::TEXT_BODY),
            ]
            .spacing(theme::SPACE_XS)
            .align_y(Alignment::Center);

            button(label)
                .style(theme::ghost())
                .padding([theme::SPACE_SM, theme::SPACE_MD])
                .into()
        }
        TunnelStatus::Disconnected | TunnelStatus::Error(_) => {
            let label = row![
                theme::icon(theme::icons::POWER),
                text("Connect").size(theme::TEXT_BODY),
            ]
            .spacing(theme::SPACE_XS)
            .align_y(Alignment::Center);

            if let Some(name) = &state.active_profile {
                let name = name.clone();
                button(label)
                    .on_press(Message::ConnectProfile(name))
                    .style(theme::primary())
                    .padding([theme::SPACE_SM, theme::SPACE_MD])
                    .into()
            } else {
                button(label)
                    .style(theme::ghost())
                    .padding([theme::SPACE_SM, theme::SPACE_MD])
                    .into()
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats section (Connected + live data only)
// ─────────────────────────────────────────────────────────────────────────────

fn stats_section(state: &State) -> Element<'_, Message> {
    let Some(live) = &state.live_status else {
        // Nothing to show if not connected / no live data.
        return iced::widget::Space::new().into();
    };

    // Aggregate rx/tx across all peers.
    let total_rx: u64 = live.peers.iter().map(|p| p.rx_bytes).sum();
    let total_tx: u64 = live.peers.iter().map(|p| p.tx_bytes).sum();

    // Latest handshake across peers.
    let latest_handshake = live.peers.iter().filter_map(|p| p.last_handshake).max();

    // Endpoint of first peer with one.
    let endpoint = live.peers.iter().find_map(|p| p.endpoint.as_deref());

    // Connected duration from connected_since.
    let duration_str = match state.connected_since {
        Some(since) => {
            let secs = since.elapsed().as_secs();
            format_uptime(secs)
        }
        None => "—".to_owned(),
    };

    // Handshake age.
    let handshake_str = match latest_handshake {
        Some(hs) => {
            let age = SystemTime::now()
                .duration_since(hs)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format_duration(age)
        }
        None => "never".to_owned(),
    };

    // Public IP.
    let ip_str = match &state.public_ip {
        Some(ip) => ip.as_str(),
        None => {
            if state.public_ip_loading {
                "fetching\u{2026}"
            } else {
                "—"
            }
        }
    };

    // Build the bar-sparkline from throughput history.
    let sparkline_data: Vec<(u64, u64)> = state.throughput_history.iter().copied().collect();
    let sparkline_el: Element<'_, Message> = bar_sparkline(&sparkline_data);

    // Tiles layout: two rows of three.
    let row1 = row![
        stat_tile(
            "Endpoint",
            endpoint.unwrap_or("—").to_owned(),
            None::<Element<'_, Message>>,
        ),
        stat_tile("Duration", duration_str, None::<Element<'_, Message>>),
        stat_tile(
            "Transfer",
            format!("\u{2193} {}  \u{2191} {}", format_bytes(total_rx), format_bytes(total_tx)),
            Some(sparkline_el),
        ),
    ]
    .spacing(theme::SPACE_SM);

    let row2 = row![
        stat_tile(
            "Last Handshake",
            handshake_str,
            None::<Element<'_, Message>>,
        ),
        stat_tile("Public IP", ip_str.to_owned(), None::<Element<'_, Message>>),
        // Spacer tile to keep the grid balanced.
        iced::widget::Space::new().width(Length::Fill),
    ]
    .spacing(theme::SPACE_SM);

    column![row1, row2]
        .spacing(theme::SPACE_SM)
        .width(Length::Fill)
        .into()
}

/// A single stat tile: a surface card with a muted label and a value.
/// Optionally includes an extra widget (sparkline) below the value.
///
/// Takes the `value` by owned `String` so callers can pass freshly-`format!`ed
/// text without lifetime gymnastics (the text widget owns its fragment).
fn stat_tile<'a>(
    label: &'a str,
    value: String,
    extra: Option<impl Into<Element<'a, Message>>>,
) -> Element<'a, Message> {
    let mut col = column![
        theme::muted(label),
        theme::body(value),
    ]
    .spacing(theme::SPACE_XS);

    if let Some(w) = extra {
        col = col.push(w.into());
    }

    container(col)
        .padding(theme::CARD_PADDING)
        .style(theme::surface_style)
        .width(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolbar: New | Import | Server | Settings
// ─────────────────────────────────────────────────────────────────────────────

fn toolbar<'a>() -> Element<'a, Message> {
    let new_btn = icon_btn(theme::icons::PLUS, "New", Message::OpenNewProfile);
    let import_btn = icon_btn(theme::icons::IMPORT, "Import", Message::ImportProfile);
    let server_btn = icon_btn(theme::icons::SERVER, "Server", Message::OpenServer);
    let settings_btn = icon_btn(theme::icons::GEAR, "Settings", Message::OpenSettings);

    row![new_btn, import_btn, server_btn, settings_btn]
        .spacing(theme::SPACE_SM)
        .align_y(Alignment::Center)
        .into()
}

/// Build a compact toolbar button: icon glyph + label, icon_button style.
fn icon_btn<'a>(glyph: &'a str, label: &'a str, msg: Message) -> Element<'a, Message> {
    let content = row![
        theme::icon(glyph),
        text(label).size(theme::TEXT_BODY),
    ]
    .spacing(theme::SPACE_XS)
    .align_y(Alignment::Center);

    button(content)
        .on_press(msg)
        .style(theme::icon_button())
        .padding([theme::SPACE_XS, theme::SPACE_SM])
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Throughput bar-sparkline (pure iced widgets, no canvas feature needed)
// ─────────────────────────────────────────────────────────────────────────────

/// Render a compact bar-sparkline from cumulative `(rx, tx)` byte history.
///
/// Derives per-interval deltas from the samples, then draws a row of thin
/// vertical `container` bars — blue (rx) stacked above grey (tx) — scaled to
/// the max delta observed.  Capped to the last 20 samples for a tight visual.
/// Returns an owned `Element<'static, Message>` so it fits inside `stat_tile`.
fn bar_sparkline(data: &[(u64, u64)]) -> Element<'static, Message> {
    const BAR_H: f32 = 28.0; // total bar height (px)
    const BAR_W: f32 = 4.0;  // bar width
    const MAX_BARS: usize = 20;

    // Need at least two points for one delta.
    if data.len() < 2 {
        return iced::widget::Space::new()
            .width(Length::Fixed(80.0))
            .height(Length::Fixed(BAR_H))
            .into();
    }

    // Deltas (rate per tick) for the last MAX_BARS intervals.
    let window_start = data.len().saturating_sub(MAX_BARS + 1);
    let window = &data[window_start..];
    let deltas: Vec<(u64, u64)> = window
        .windows(2)
        .map(|w| {
            (
                w[1].0.saturating_sub(w[0].0),
                w[1].1.saturating_sub(w[0].1),
            )
        })
        .collect();

    let max_val = deltas
        .iter()
        .map(|(rx, tx)| rx.max(tx))
        .copied()
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    // Build the bar row as owned containers, collecting into an owned column.
    let bars: Vec<Element<'static, Message>> = deltas
        .into_iter()
        .map(|(rx, tx)| {
            let rx_h = (rx as f32 / max_val * BAR_H * 0.85).max(1.0);
            let tx_h = (tx as f32 / max_val * BAR_H * 0.85).max(1.0);

            // rx bar (accent blue).
            let rx_bar = container(
                iced::widget::Space::new()
                    .width(Length::Fixed(BAR_W))
                    .height(Length::Fixed(rx_h)),
            )
            .style(|_theme: &iced::Theme| container::Style {
                background: Some(Background::Color(Color {
                    r: 0.231,
                    g: 0.510,
                    b: 0.965,
                    a: 0.85,
                })),
                ..container::Style::default()
            });

            // tx bar (muted grey).
            let tx_bar = container(
                iced::widget::Space::new()
                    .width(Length::Fixed(BAR_W))
                    .height(Length::Fixed(tx_h)),
            )
            .style(|_theme: &iced::Theme| container::Style {
                background: Some(Background::Color(Color {
                    r: 0.580,
                    g: 0.624,
                    b: 0.694,
                    a: 0.65,
                })),
                ..container::Style::default()
            });

            // Stack rx above tx, anchored to the bottom.
            let bar_col: Element<'static, Message> = column![rx_bar, tx_bar]
                .spacing(1)
                .into();

            // Wrap in a fixed-height container, aligned to the bottom.
            container(bar_col)
                .width(Length::Fixed(BAR_W + 2.0))
                .height(Length::Fixed(BAR_H))
                .align_y(iced::alignment::Vertical::Bottom)
                .into()
        })
        .collect();

    // Assemble bars into a row.
    let bar_row = row(bars).spacing(2).align_y(Alignment::End);

    container(bar_row)
        .width(Length::Fixed(80.0))
        .height(Length::Fixed(BAR_H))
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers (pure, no I/O)
// ─────────────────────────────────────────────────────────────────────────────

/// Format a connected-for uptime in seconds as "2h 14m", "45s", etc.
fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        format!("{m}m {s:02}s")
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m:02}m")
    }
}

/// Format a handshake age in seconds as "2 minutes ago", etc.
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

    // ── format_bytes ──────────────────────────────────────────────────────────

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

    // ── format_duration ───────────────────────────────────────────────────────

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

    // ── format_uptime ─────────────────────────────────────────────────────────

    #[test]
    fn uptime_seconds_only() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
    }

    #[test]
    fn uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(60), "1m 00s");
        assert_eq!(format_uptime(90), "1m 30s");
        assert_eq!(format_uptime(3599), "59m 59s");
    }

    #[test]
    fn uptime_hours_and_minutes() {
        assert_eq!(format_uptime(3600), "1h 00m");
        assert_eq!(format_uptime(7384), "2h 03m");
    }
}
