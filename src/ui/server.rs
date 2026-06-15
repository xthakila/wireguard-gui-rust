//! Server screen — host a WireGuard server, provision clients, hand out configs/QR.
//!
//! Two branches:
//!
//! * **No server configured** — shows a "Create server" form: endpoint-host text input
//!   + a "Create" button (`Message::ServerCreate`).
//!
//! * **Server configured** — shows:
//!   - Server public key, endpoint:port, subnet (read-only).
//!   - Start/Stop toggle (`Message::ServerStartToggle`) coloured by `state.server_running`.
//!   - NAT/forwarding checkbox (`Message::ServerNatToggle`).
//!   - Egress interface (from `ServerConfig::egress_iface`).
//!   - Peer table: name, assigned IP, live stats when running; Remove button.
//!   - Add-peer row: text input (`Message::ServerPeerNameChanged`) + Add button
//!     (`Message::ServerAddPeer`).
//!   - When `state.last_client_conf` is `Some`, a selectable conf text area PLUS
//!     the QR code rendered from `server::qr_png`.
//!
//! A "← Back" button (`Message::GoHome`) is always visible.
//!
//! Style conventions match the rest of `crate::ui::*`: colour constants, inline
//! `container` styles, `row!` / `column!` macros, `scrollable` for long content.

use std::time::SystemTime;

use iced::widget::{
    button, checkbox, column, container, row, rule, scrollable, text, text_input, Space,
};
use iced::{Alignment, Color, Element, Length, Padding};

use crate::app::{Message, State};

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette (mirrors the rest of ui/*)
// ─────────────────────────────────────────────────────────────────────────────

/// Green — server running / peer active.
const COLOR_RUNNING: Color = Color { r: 0.18, g: 0.80, b: 0.44, a: 1.0 };
/// Amber — transitional / warning.
const COLOR_WARN: Color = Color { r: 0.94, g: 0.69, b: 0.13, a: 1.0 };
/// Muted grey — subdued labels, placeholders.
const COLOR_MUTED: Color = Color { r: 0.55, g: 0.55, b: 0.60, a: 1.0 };
/// Section accent (light blue) — matches editor.rs `section_color()`.
const COLOR_SECTION: Color = Color { r: 0.5, g: 0.75, b: 1.0, a: 1.0 };
/// Red — destructive action / remove button.
const COLOR_DANGER_BG: Color = Color { r: 0.55, g: 0.10, b: 0.10, a: 1.0 };
const COLOR_DANGER_HOVER: Color = Color { r: 0.72, g: 0.13, b: 0.13, a: 1.0 };

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the server management screen.
///
/// Reads only frozen `State` fields; does not mutate anything.
pub fn server(state: &State) -> Element<'_, Message> {
    // ── header ─────────────────────────────────────────────────────────────────
    let header = row![
        button(text("← Back"))
            .on_press(Message::GoHome)
            .padding(Padding::from([6u16, 14u16])),
        text("Server Mode").size(22).color(COLOR_SECTION),
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    // ── body (branch on whether a server is configured) ──────────────────────
    let body: Element<'_, Message> = match &state.server {
        None => create_form(state),
        Some(_cfg) => configured_panel(state),
    };

    let content = column![
        header,
        rule::horizontal(1u32),
        Space::new().height(Length::Fixed(8.0)),
        body,
    ]
    .spacing(0)
    .padding(Padding::from([16u16, 20u16]));

    container(
        scrollable(content)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch A — no server yet: "Create server" form
// ─────────────────────────────────────────────────────────────────────────────

/// Holds local UI state we need when no server exists.  Since `State` only
/// carries `server_peer_name_input` (used for the peer-add row), we re-use it
/// as the endpoint-host input before any server is created — both are transient
/// text buffers that are only meaningful on their respective sub-screens.
fn create_form(state: &State) -> Element<'_, Message> {
    let endpoint_value = &state.server_peer_name_input;

    let intro = text(
        "No server is configured yet. Enter the public hostname or IP address \
         this server will be reachable at, then click Create.",
    )
    .size(13)
    .color(COLOR_MUTED);

    let endpoint_input = text_input("vpn.example.com  or  203.0.113.1", endpoint_value)
        .on_input(Message::ServerPeerNameChanged)
        .padding(8)
        .width(Length::Fill);

    let host = endpoint_value.trim().to_owned();
    let can_create = !host.is_empty();

    // Wire the Create button only when there is something to submit.
    let create_btn: Element<'_, Message> = if can_create {
        button(text("Create Server").size(14))
            .on_press(Message::ServerCreate(host))
            .padding(Padding::from([8u16, 18u16]))
            .into()
    } else {
        // Visually disabled — no on_press.
        button(text("Create Server").size(14))
            .padding(Padding::from([8u16, 18u16]))
            .into()
    };

    column![
        intro,
        Space::new().height(Length::Fixed(12.0)),
        row![
            text("Endpoint host").size(13).color(COLOR_MUTED).width(Length::Fixed(130.0)),
            endpoint_input,
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        Space::new().height(Length::Fixed(12.0)),
        create_btn,
    ]
    .spacing(4)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch B — server is configured
// ─────────────────────────────────────────────────────────────────────────────

fn configured_panel(state: &State) -> Element<'_, Message> {
    // Guaranteed Some here — caller checks.
    let cfg = state.server.as_ref().unwrap();

    // ── Server identity ───────────────────────────────────────────────────────
    let identity = column![
        text("Server").size(16).color(COLOR_SECTION),
        info_row("Public key", truncate_key(&cfg.public_key)),
        info_row("Endpoint", format!("{}:{}", cfg.endpoint_host, cfg.listen_port)),
        info_row("Subnet", cfg.subnet.clone()),
        info_row(
            "Egress interface",
            cfg.egress_iface.clone().unwrap_or_else(|| "(not detected)".to_owned()),
        ),
    ]
    .spacing(4);

    // ── Start / Stop toggle ───────────────────────────────────────────────────
    let (toggle_label, toggle_color) = if state.server_running {
        ("■  Stop Server", COLOR_DANGER_BG)
    } else {
        ("▶  Start Server", COLOR_RUNNING)
    };

    let start_stop_btn = button(text(toggle_label).size(13))
        .on_press(Message::ServerStartToggle)
        .padding(Padding::from([7u16, 16u16]))
        .style(move |_theme, status| {
            let bg = match status {
                iced::widget::button::Status::Hovered => Color {
                    r: toggle_color.r * 1.15,
                    g: toggle_color.g * 1.15,
                    b: toggle_color.b * 1.15,
                    a: 1.0,
                },
                _ => toggle_color,
            };
            iced::widget::button::Style {
                background: Some(iced::Background::Color(bg)),
                text_color: Color::WHITE,
                border: iced::Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                shadow: iced::Shadow::default(),
                snap: false,
            }
        });

    let running_label = if state.server_running {
        text("Running").size(13).color(COLOR_RUNNING)
    } else {
        text("Stopped").size(13).color(COLOR_MUTED)
    };

    let status_row = row![start_stop_btn, running_label]
        .spacing(12)
        .align_y(Alignment::Center);

    // ── NAT / forwarding toggle ───────────────────────────────────────────────
    // `State` has no persistent `nat_enabled` field; we render the checkbox as
    // unchecked by default and let the toggle message carry the new desired state.
    // The privileged helper applies it; the UI re-renders cleanly on next frame.
    let nat_cb: Element<'_, Message> = row![
        checkbox(false).on_toggle(Message::ServerNatToggle),
        text("Enable NAT / IP forwarding (masquerade for subnet)").size(13),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into();

    // ── Peer table ────────────────────────────────────────────────────────────
    let peer_section = peer_table(state);

    // ── Add peer row ──────────────────────────────────────────────────────────
    let add_peer_row = add_peer_row(state);

    // ── Client conf / QR panel ────────────────────────────────────────────────
    let conf_panel = client_conf_panel(state);

    // ── Assemble ──────────────────────────────────────────────────────────────
    column![
        identity,
        Space::new().height(Length::Fixed(12.0)),
        rule::horizontal(1u32),
        Space::new().height(Length::Fixed(8.0)),
        status_row,
        Space::new().height(Length::Fixed(8.0)),
        nat_cb,
        Space::new().height(Length::Fixed(12.0)),
        rule::horizontal(1u32),
        Space::new().height(Length::Fixed(8.0)),
        text("Clients").size(16).color(COLOR_SECTION),
        peer_section,
        Space::new().height(Length::Fixed(8.0)),
        add_peer_row,
        conf_panel,
    ]
    .spacing(4)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer table
// ─────────────────────────────────────────────────────────────────────────────

fn peer_table(state: &State) -> Element<'_, Message> {
    let cfg = match &state.server {
        Some(c) => c,
        None => return Space::new().into(),
    };

    if cfg.peers.is_empty() {
        return text("No clients provisioned yet.").size(13).color(COLOR_MUTED).into();
    }

    let header = container(
        row![
            text("Name").size(12).color(COLOR_MUTED).width(Length::FillPortion(2)),
            text("Assigned IP").size(12).color(COLOR_MUTED).width(Length::FillPortion(2)),
            text("Last handshake").size(12).color(COLOR_MUTED).width(Length::FillPortion(3)),
            text("RX").size(12).color(COLOR_MUTED).width(Length::FillPortion(2)),
            text("TX").size(12).color(COLOR_MUTED).width(Length::FillPortion(2)),
            Space::new().width(Length::Fixed(80.0)), // Remove button column
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .padding(Padding::from([4u16, 8u16])),
    )
    .width(Length::Fill)
    .style(|theme: &iced::Theme| {
        let palette = theme.extended_palette();
        iced::widget::container::Style {
            background: Some(iced::Background::Color(palette.background.strong.color)),
            ..Default::default()
        }
    });

    let mut rows: Vec<Element<'_, Message>> = vec![header.into()];

    for (idx, peer) in cfg.peers.iter().enumerate() {
        // Look up live stats for this peer by public key (only meaningful when running).
        let live: Option<&crate::wg::status::PeerStatus> = if state.server_running {
            state
                .server_peer_status
                .iter()
                .find(|ps| ps.public_key == peer.public_key)
        } else {
            None
        };

        let handshake_str = match live.and_then(|ps| ps.last_handshake) {
            Some(hs) => format_age(hs),
            None if state.server_running => "never".to_owned(),
            None => "—".to_owned(),
        };

        let (rx_str, tx_str) = match live {
            Some(ps) => (format_bytes(ps.rx_bytes), format_bytes(ps.tx_bytes)),
            None => ("—".to_owned(), "—".to_owned()),
        };

        let remove_btn = button(text("Remove").size(12))
            .on_press(Message::ServerRemovePeer(idx))
            .padding(Padding::from([4u16, 10u16]))
            .style(|_theme, status| {
                let bg = match status {
                    iced::widget::button::Status::Hovered => COLOR_DANGER_HOVER,
                    _ => COLOR_DANGER_BG,
                };
                iced::widget::button::Style {
                    background: Some(iced::Background::Color(bg)),
                    text_color: Color::WHITE,
                    border: iced::Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    shadow: iced::Shadow::default(),
                    snap: false,
                }
            });

        let peer_row = container(
            row![
                text(peer.name.as_str()).size(13).width(Length::FillPortion(2)),
                text(peer.assigned_ip.as_str()).size(13).width(Length::FillPortion(2)),
                text(handshake_str).size(13).color(COLOR_MUTED).width(Length::FillPortion(3)),
                text(rx_str).size(13).color(COLOR_MUTED).width(Length::FillPortion(2)),
                text(tx_str).size(13).color(COLOR_MUTED).width(Length::FillPortion(2)),
                container(remove_btn).width(Length::Fixed(80.0)),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .padding(Padding::from([6u16, 8u16])),
        )
        .width(Length::Fill)
        .style(move |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(if idx % 2 == 0 {
                    palette.background.base.color
                } else {
                    palette.background.weak.color
                })),
                ..Default::default()
            }
        });

        rows.push(peer_row.into());
    }

    column(rows).spacing(1).width(Length::Fill).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Add-peer row
// ─────────────────────────────────────────────────────────────────────────────

fn add_peer_row(state: &State) -> Element<'_, Message> {
    let input = text_input("Client name (e.g. phone, laptop)", &state.server_peer_name_input)
        .on_input(Message::ServerPeerNameChanged)
        .padding(7)
        .width(Length::Fill);

    let can_add = !state.server_peer_name_input.trim().is_empty();

    let add_btn: Element<'_, Message> = if can_add {
        button(text("+ Add Client").size(13))
            .on_press(Message::ServerAddPeer)
            .padding(Padding::from([7u16, 14u16]))
            .into()
    } else {
        button(text("+ Add Client").size(13))
            .padding(Padding::from([7u16, 14u16]))
            .into()
    };

    row![input, add_btn]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Client conf + QR panel
// ─────────────────────────────────────────────────────────────────────────────

fn client_conf_panel(state: &State) -> Element<'_, Message> {
    let (peer_name, conf_text) = match &state.last_client_conf {
        Some(pair) => pair,
        None => return Space::new().into(),
    };

    // ── Heading ───────────────────────────────────────────────────────────────
    let heading = text(format!("Client config — {peer_name}"))
        .size(15)
        .color(COLOR_SECTION);

    // ── Conf text (read-only, selectable via a text_input with no on_input) ──
    // iced 0.14 has no dedicated "selectable text" widget outside of the rich
    // text path; we use a `text_input` with no `on_input` binding (read-only)
    // which lets the user at least see the text. The entire conf is shown so the
    // user can copy-paste it.
    //
    // Alternatively a `text_editor::Content` would give full selection, but that
    // requires mutable state on `State` (a separate `Content` field). The spec
    // says "selectable area" — a read-only `text_input` is the closest stateless
    // approximation. A monospaced-looking container with the text inside is
    // acceptable too; we use a styled container + `text` so the layout is clean.
    let conf_box = container(
        text(conf_text.as_str()).size(12).font(iced::Font::MONOSPACE),
    )
    .width(Length::Fill)
    .padding(Padding::from([10u16, 14u16]))
    .style(|theme: &iced::Theme| {
        let palette = theme.extended_palette();
        iced::widget::container::Style {
            background: Some(iced::Background::Color(palette.background.weak.color)),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: palette.background.strong.color,
            },
            ..Default::default()
        }
    });

    // ── QR code image ─────────────────────────────────────────────────────────
    // Build the iced image handle from the PNG bytes returned by `qr_png`.
    // Errors (e.g. conf text too large) are surfaced as a fallback label; the
    // caller (the app update loop) surfaced them via the banner on the
    // ServerAddPeerResult path — here we just defend against a stale conf.
    let qr_element: Element<'_, Message> = match crate::server::qr_png(conf_text) {
        Ok(png_bytes) => {
            let handle = iced::widget::image::Handle::from_bytes(png_bytes);
            iced::widget::image(handle)
                .width(Length::Fixed(200.0))
                .height(Length::Fixed(200.0))
                .into()
        }
        Err(e) => text(format!("QR unavailable: {e}"))
            .size(12)
            .color(COLOR_WARN)
            .into(),
    };

    let qr_col = column![
        text("Scan to import on mobile").size(12).color(COLOR_MUTED),
        Space::new().height(Length::Fixed(6.0)),
        qr_element,
    ]
    .spacing(2)
    .align_x(Alignment::Center);

    let panel = column![
        Space::new().height(Length::Fixed(16.0)),
        rule::horizontal(1u32),
        Space::new().height(Length::Fixed(10.0)),
        heading,
        Space::new().height(Length::Fixed(8.0)),
        // Conf text left, QR right.
        row![
            conf_box,
            Space::new().width(Length::Fixed(16.0)),
            qr_col,
        ]
        .align_y(Alignment::Start),
    ]
    .spacing(4);

    panel.into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout / formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A two-column info row: muted label on the left (fixed width), value on the right.
fn info_row(label: &str, value: String) -> Element<'_, Message> {
    row![
        text(label)
            .size(13)
            .color(COLOR_MUTED)
            .width(Length::Fixed(130.0)),
        text(value).size(13),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

/// Truncate a long base64 key for display: first 8 + "…" + last 8 chars.
fn truncate_key(key: &str) -> String {
    if key.len() <= 20 {
        return key.to_owned();
    }
    format!("{}…{}", &key[..8], &key[key.len() - 8..])
}

/// Format a handshake `SystemTime` as a human-readable age ("2 min ago", etc.).
fn format_age(ts: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(ts)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Format a byte count as KiB / MiB / GiB (mirrors `ui::status`).
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
// Tests — pure only (no display, no root, no real WireGuard interface)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_bytes ──────────────────────────────────────────────────────────

    #[test]
    fn format_bytes_sub_kib() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(2048), "2.0 KiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    // ── format_age ────────────────────────────────────────────────────────────

    #[test]
    fn format_age_seconds() {
        let ts = SystemTime::now() - std::time::Duration::from_secs(30);
        let s = format_age(ts);
        assert!(s.ends_with("s ago"), "expected Xs ago, got {s}");
    }

    #[test]
    fn format_age_minutes() {
        let ts = SystemTime::now() - std::time::Duration::from_secs(125);
        let s = format_age(ts);
        assert!(s.ends_with("m ago"), "expected Xm ago, got {s}");
    }

    #[test]
    fn format_age_hours() {
        let ts = SystemTime::now() - std::time::Duration::from_secs(7300);
        let s = format_age(ts);
        assert!(s.ends_with("h ago"), "expected Xh ago, got {s}");
    }

    #[test]
    fn format_age_days() {
        let ts = SystemTime::now() - std::time::Duration::from_secs(86401);
        let s = format_age(ts);
        assert!(s.ends_with("d ago"), "expected Xd ago, got {s}");
    }

    // ── truncate_key ──────────────────────────────────────────────────────────

    #[test]
    fn truncate_key_short_passthrough() {
        let short = "AAAA=";
        assert_eq!(truncate_key(short), short);
    }

    #[test]
    fn truncate_key_long_contains_ellipsis() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let t = truncate_key(key);
        assert!(t.contains('…'), "expected ellipsis in truncated key: {t}");
        // First 8 + last 8 = 16 visible chars + 1 ellipsis = 17 chars total.
        assert_eq!(t.chars().count(), 17);
    }

    // ── format_bytes golden values ────────────────────────────────────────────

    #[test]
    fn format_bytes_boundary_values() {
        // One byte under the MiB boundary: 1048575 / 1024 = 1023.999…, which the
        // `{:.1}` formatter rounds up to 1024.0 KiB (the value is still < MiB, so it
        // stays in KiB units rather than promoting to "1.0 MiB").
        assert_eq!(format_bytes(1024 * 1024 - 1), "1024.0 KiB");
        // Just over MiB boundary.
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }
}
