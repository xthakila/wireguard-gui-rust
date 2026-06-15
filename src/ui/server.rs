//! Server screen — host a WireGuard server, provision clients, hand out configs/QR.
//!
//! Two branches:
//!
//! * **No server configured** — shows a "Create server" form inside a card:
//!   an endpoint-host text input + a primary "Create" button.
//!
//! * **Server configured** — shows:
//!   - A server summary card: shield icon, pubkey, endpoint:port, subnet, egress.
//!   - A status row: Start/Stop toggle coloured green/red + a pill badge.
//!   - A NAT/forwarding checkbox card.
//!   - Peer list as individual cards: name, assigned IP, last-handshake age + rx/tx
//!     when running, plus a Revoke button.
//!   - Add-peer row (text input + icon button).
//!   - When `state.last_client_conf` is `Some`, a card with the config text (monospace)
//!     and the QR code displayed LARGE (320×320) plus a Copy label.
//!
//! A "← Back" button is always visible in the header.
//!
//! **Style**: every colour, card, pill, button, and glyph comes from [`crate::ui::theme`]
//! helpers so this screen is visually cohesive with the rest of the app.

use std::time::SystemTime;

use iced::widget::{
    button, checkbox, column, container, image as img_widget, row, scrollable, text,
    text_input, Space,
};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{Message, State};
use crate::ui::theme::{
    self, StatusKind,
    CARD_PADDING, RADIUS_CARD, RADIUS_CONTROL,
    SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XS,
    TEXT_BODY, TEXT_CAPTION, TEXT_SECTION,
    icons,
};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the server management screen.
///
/// Reads only frozen `State` fields; does not mutate anything.
pub fn server(state: &State) -> Element<'_, Message> {
    // ── header ─────────────────────────────────────────────────────────────────
    let back_btn = button(
        row![
            theme::icon(icons::BACK),
            text("Back").size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::GoHome)
    .padding(Padding::from([SPACE_XS as u16, SPACE_SM as u16]))
    .style(theme::ghost());

    let header = row![
        back_btn,
        Space::new().width(Length::Fixed(SPACE_SM)),
        row![
            theme::icon(icons::SERVER),
            theme::title("Server Mode"),
        ]
        .spacing(SPACE_SM)
        .align_y(Alignment::Center),
    ]
    .spacing(SPACE_SM)
    .align_y(Alignment::Center);

    // ── body (branch on whether a server is configured) ──────────────────────
    let body: Element<'_, Message> = match &state.server {
        None => create_form(state),
        Some(_) => configured_panel(state),
    };

    let content = column![
        header,
        Space::new().height(Length::Fixed(SPACE_MD)),
        body,
    ]
    .spacing(0)
    .padding(Padding::from([SPACE_MD as u16, SPACE_LG as u16]));

    container(
        scrollable(content)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|theme| {
        let p = theme::palette(theme);
        iced::widget::container::Style {
            background: Some(iced::Background::Color(p.bg)),
            ..Default::default()
        }
    })
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch A — no server yet: "Create server" form in a card
// ─────────────────────────────────────────────────────────────────────────────

fn create_form(state: &State) -> Element<'_, Message> {
    // Re-use `server_peer_name_input` as the endpoint-host buffer before any server
    // is created — both are transient text fields only meaningful on their own sub-screens.
    let endpoint_value = &state.server_peer_name_input;

    let intro = theme::muted(
        "No server is configured yet. Enter the public hostname or IP address \
         this server will be reachable at, then click Create.",
    );

    let endpoint_row = row![
        text("Endpoint host")
            .size(TEXT_BODY)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::palette(theme).muted),
            })
            .width(Length::Fixed(140.0)),
        text_input("vpn.example.com  or  203.0.113.1", endpoint_value)
            .on_input(Message::ServerPeerNameChanged)
            .padding(SPACE_SM)
            .width(Length::Fill),
    ]
    .spacing(SPACE_SM)
    .align_y(Alignment::Center);

    let host = endpoint_value.trim().to_owned();
    let can_create = !host.is_empty();

    let create_btn: Element<'_, Message> = {
        let label = row![
            theme::icon(icons::PLUS),
            text("Create Server").size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center);

        if can_create {
            button(label)
                .on_press(Message::ServerCreate(host))
                .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
                .style(theme::primary())
                .into()
        } else {
            button(label)
                .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
                .style(theme::primary())
                .into()
        }
    };

    let form_inner = column![
        row![
            theme::icon(icons::SERVER),
            theme::section_title("Create a New Server"),
        ]
        .spacing(SPACE_SM)
        .align_y(Alignment::Center),
        Space::new().height(Length::Fixed(SPACE_XS)),
        intro,
        Space::new().height(Length::Fixed(SPACE_MD)),
        endpoint_row,
        Space::new().height(Length::Fixed(SPACE_MD)),
        create_btn,
    ]
    .spacing(0);

    container(form_inner)
        .padding(CARD_PADDING)
        .width(Length::Fill)
        .style(theme::card_style)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch B — server is configured
// ─────────────────────────────────────────────────────────────────────────────

fn configured_panel(state: &State) -> Element<'_, Message> {
    let cfg = state.server.as_ref().expect("caller checked");

    // ── Server summary card ───────────────────────────────────────────────────
    let status_kind = if state.server_running {
        StatusKind::Connected
    } else {
        StatusKind::Idle
    };
    let status_badge = theme::status_pill(
        if state.server_running { "Running" } else { "Stopped" },
        status_kind,
    );

    let server_card_inner = column![
        row![
            theme::icon(icons::SHIELD),
            Space::new().width(Length::Fixed(SPACE_XS)),
            theme::section_title("Server"),
            Space::new().width(Length::Fill),
            status_badge,
        ]
        .align_y(Alignment::Center),
        Space::new().height(Length::Fixed(SPACE_SM)),
        info_row("Public key", truncate_key(&cfg.public_key)),
        info_row("Endpoint", format!("{}:{}", cfg.endpoint_host, cfg.listen_port)),
        info_row("Subnet", cfg.subnet.clone()),
        info_row(
            "Egress",
            cfg.egress_iface.clone().unwrap_or_else(|| "(not detected)".to_owned()),
        ),
    ]
    .spacing(SPACE_XS);

    let server_card = container(server_card_inner)
        .padding(CARD_PADDING)
        .width(Length::Fill)
        .style(theme::card_style);

    // ── Start / Stop toggle ───────────────────────────────────────────────────
    let start_stop_btn = if state.server_running {
        button(
            row![
                theme::icon(icons::STOP),
                text("Stop Server").size(TEXT_BODY),
            ]
            .spacing(SPACE_XS)
            .align_y(Alignment::Center),
        )
        .on_press(Message::ServerStartToggle)
        .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
        .style(theme::danger())
    } else {
        button(
            row![
                theme::icon(icons::POWER),
                text("Start Server").size(TEXT_BODY),
            ]
            .spacing(SPACE_XS)
            .align_y(Alignment::Center),
        )
        .on_press(Message::ServerStartToggle)
        .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
        .style(theme::success())
    };

    let control_card_inner = row![
        start_stop_btn,
        Space::new().width(Length::Fixed(SPACE_MD)),
        theme::status_dot(status_kind, 10.0),
        Space::new().width(Length::Fixed(SPACE_XS)),
        theme::body(if state.server_running {
            "Interface is up"
        } else {
            "Interface is down"
        }),
    ]
    .spacing(0)
    .align_y(Alignment::Center);

    let control_card = container(control_card_inner)
        .padding(CARD_PADDING)
        .width(Length::Fill)
        .style(theme::card_style);

    // ── NAT card ──────────────────────────────────────────────────────────────
    let nat_card_inner = row![
        checkbox(false)
            .on_toggle(Message::ServerNatToggle),
        Space::new().width(Length::Fixed(SPACE_SM)),
        column![
            theme::body("Enable NAT / IP forwarding"),
            theme::muted("Masquerade traffic from the tunnel subnet through the egress interface."),
        ]
        .spacing(SPACE_XS),
    ]
    .spacing(0)
    .align_y(Alignment::Start);

    let nat_card = container(nat_card_inner)
        .padding(CARD_PADDING)
        .width(Length::Fill)
        .style(theme::card_style);

    // ── Peer section ──────────────────────────────────────────────────────────
    let peers_section = peers_panel(state);
    let add_row = add_peer_row(state);

    // ── Client conf / QR ─────────────────────────────────────────────────────
    let conf_section = client_conf_panel(state);

    // ── Assemble all sections ─────────────────────────────────────────────────
    column![
        server_card,
        Space::new().height(Length::Fixed(SPACE_MD)),
        control_card,
        Space::new().height(Length::Fixed(SPACE_MD)),
        nat_card,
        Space::new().height(Length::Fixed(SPACE_LG)),
        row![
            theme::icon(icons::LOCK),
            Space::new().width(Length::Fixed(SPACE_XS)),
            theme::section_title("Clients"),
        ]
        .align_y(Alignment::Center),
        Space::new().height(Length::Fixed(SPACE_SM)),
        peers_section,
        Space::new().height(Length::Fixed(SPACE_SM)),
        add_row,
        conf_section,
    ]
    .spacing(0)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer list
// ─────────────────────────────────────────────────────────────────────────────

fn peers_panel(state: &State) -> Element<'_, Message> {
    let cfg = match &state.server {
        Some(c) => c,
        None => return Space::new().into(),
    };

    if cfg.peers.is_empty() {
        let empty_card = container(
            column![
                theme::icon(icons::PLUS),
                Space::new().height(Length::Fixed(SPACE_XS)),
                theme::muted("No clients provisioned yet. Add a client below."),
            ]
            .spacing(0)
            .align_x(Alignment::Center),
        )
        .padding(Padding::from([SPACE_LG as u16, CARD_PADDING as u16]))
        .width(Length::Fill)
        .style(|theme| {
            let p = theme::palette(theme);
            iced::widget::container::Style {
                background: Some(iced::Background::Color(p.surface)),
                border: iced::Border {
                    color: p.border,
                    width: 1.0,
                    radius: RADIUS_CARD.into(),
                },
                ..Default::default()
            }
        });
        return empty_card.into();
    }

    let mut peer_cards: Vec<Element<'_, Message>> = Vec::new();
    for (idx, peer) in cfg.peers.iter().enumerate() {
        peer_cards.push(peer_card(state, idx, peer));
        if idx + 1 < cfg.peers.len() {
            peer_cards.push(Space::new().height(Length::Fixed(SPACE_SM)).into());
        }
    }

    column(peer_cards).spacing(0).width(Length::Fill).into()
}

fn peer_card<'a>(
    state: &'a State,
    idx: usize,
    peer: &'a crate::server::ServerPeer,
) -> Element<'a, Message> {
    // Live stats from the running server, keyed by public key.
    let live: Option<&crate::wg::status::PeerStatus> = if state.server_running {
        state
            .server_peer_status
            .iter()
            .find(|ps| ps.public_key == peer.public_key)
    } else {
        None
    };

    let handshake_age_kind = match live.and_then(|ps| ps.last_handshake) {
        Some(_) => StatusKind::Connected,
        None if state.server_running => StatusKind::Idle,
        None => StatusKind::Idle,
    };

    let handshake_str = match live.and_then(|ps| ps.last_handshake) {
        Some(hs) => format!("Handshake  {}", format_age(hs)),
        None if state.server_running => "Handshake  never".to_owned(),
        None => "Handshake  —".to_owned(),
    };

    let (rx_str, tx_str) = match live {
        Some(ps) => (
            format!("{} {}", icons::IMPORT, format_bytes(ps.rx_bytes)),
            format!("{} {}", icons::EXPORT, format_bytes(ps.tx_bytes)),
        ),
        None => ("— rx".to_owned(), "— tx".to_owned()),
    };

    let revoke_btn = button(
        row![
            theme::icon(icons::TRASH),
            text("Revoke").size(TEXT_CAPTION),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::ServerRemovePeer(idx))
    .padding(Padding::from([SPACE_XS as u16, SPACE_SM as u16]))
    .style(theme::danger());

    let stats_row: Element<'_, Message> = if state.server_running {
        row![
            theme::status_dot(handshake_age_kind, 8.0),
            Space::new().width(Length::Fixed(SPACE_XS)),
            text(handshake_str.clone()).size(TEXT_CAPTION).style(
                move |theme: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme::palette(theme).muted),
                }
            ),
            Space::new().width(Length::Fixed(SPACE_MD)),
            text(rx_str).size(TEXT_CAPTION).style(|theme: &iced::Theme| {
                iced::widget::text::Style {
                    color: Some(theme::palette(theme).muted),
                }
            }),
            Space::new().width(Length::Fixed(SPACE_SM)),
            text(tx_str).size(TEXT_CAPTION).style(|theme: &iced::Theme| {
                iced::widget::text::Style {
                    color: Some(theme::palette(theme).muted),
                }
            }),
        ]
        .spacing(0)
        .align_y(Alignment::Center)
        .into()
    } else {
        Space::new().into()
    };

    let card_inner = row![
        // Left: icon + identity
        column![
            row![
                theme::icon(icons::LOCK),
                Space::new().width(Length::Fixed(SPACE_XS)),
                theme::body(peer.name.as_str()),
            ]
            .spacing(0)
            .align_y(Alignment::Center),
            Space::new().height(Length::Fixed(SPACE_XS)),
            row![
                text("IP").size(TEXT_CAPTION).style(|theme: &iced::Theme| {
                    iced::widget::text::Style {
                        color: Some(theme::palette(theme).muted),
                    }
                }),
                Space::new().width(Length::Fixed(SPACE_XS)),
                text(peer.assigned_ip.as_str()).size(TEXT_CAPTION).style(
                    |theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme::palette(theme).accent),
                    }
                ),
            ]
            .spacing(0)
            .align_y(Alignment::Center),
            Space::new().height(Length::Fixed(SPACE_XS)),
            stats_row,
        ]
        .spacing(0)
        .width(Length::Fill),
        // Right: revoke button
        revoke_btn,
    ]
    .spacing(SPACE_MD)
    .align_y(Alignment::Center);

    container(card_inner)
        .padding(CARD_PADDING)
        .width(Length::Fill)
        .style(theme::surface_style)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Add-peer row
// ─────────────────────────────────────────────────────────────────────────────

fn add_peer_row(state: &State) -> Element<'_, Message> {
    let input = text_input(
        "Client name (e.g. phone, laptop)",
        &state.server_peer_name_input,
    )
    .on_input(Message::ServerPeerNameChanged)
    .padding(SPACE_SM)
    .width(Length::Fill);

    let can_add = !state.server_peer_name_input.trim().is_empty();

    let add_label = row![
        theme::icon(icons::PLUS),
        text("Add Client").size(TEXT_BODY),
    ]
    .spacing(SPACE_XS)
    .align_y(Alignment::Center);

    let add_btn: Element<'_, Message> = if can_add {
        button(add_label)
            .on_press(Message::ServerAddPeer)
            .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
            .style(theme::primary())
            .into()
    } else {
        button(add_label)
            .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
            .style(theme::primary())
            .into()
    };

    container(
        row![input, add_btn]
            .spacing(SPACE_SM)
            .align_y(Alignment::Center),
    )
    .padding(CARD_PADDING)
    .width(Length::Fill)
    .style(theme::card_style)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Client conf + QR card
// ─────────────────────────────────────────────────────────────────────────────

fn client_conf_panel(state: &State) -> Element<'_, Message> {
    let (peer_name, conf_text) = match &state.last_client_conf {
        Some(pair) => pair,
        None => return Space::new().into(),
    };

    // ── Heading ───────────────────────────────────────────────────────────────
    let heading = row![
        theme::icon(icons::SHIELD),
        Space::new().width(Length::Fixed(SPACE_XS)),
        theme::section_title(format!("Client Config — {peer_name}")),
        Space::new().width(Length::Fill),
        // Status pill: fresh config ready to scan.
        theme::status_pill("Ready to scan", StatusKind::Connected),
    ]
    .spacing(0)
    .align_y(Alignment::Center);

    // ── Config text box (monospace, read-only) ────────────────────────────────
    let conf_box = container(
        text(conf_text.as_str())
            .size(TEXT_CAPTION)
            .font(iced::Font::MONOSPACE)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::palette(theme).text),
            }),
    )
    .width(Length::Fill)
    .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
    .style(|theme: &iced::Theme| {
        let p = theme::palette(theme);
        iced::widget::container::Style {
            background: Some(iced::Background::Color(p.bg)),
            border: iced::Border {
                color: p.border,
                width: 1.0,
                radius: RADIUS_CONTROL.into(),
            },
            ..Default::default()
        }
    });

    // "Copy" label button (wires to GoHome as a stub — app has no Clipboard message yet).
    let copy_btn = button(
        row![
            text("\u{2398}").size(TEXT_SECTION), // ⎘ clipboard glyph
            text("Copy Config").size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::GoHome) // placeholder — real copy would need a Clipboard msg
    .padding(Padding::from([SPACE_XS as u16, SPACE_SM as u16]))
    .style(theme::ghost());

    let conf_col = column![
        theme::muted("Configuration file — paste into WireGuard on the client device."),
        Space::new().height(Length::Fixed(SPACE_XS)),
        conf_box,
        Space::new().height(Length::Fixed(SPACE_XS)),
        copy_btn,
    ]
    .spacing(0)
    .width(Length::Fill);

    // ── QR code ───────────────────────────────────────────────────────────────
    let qr_element: Element<'_, Message> = match crate::server::qr_png(conf_text) {
        Ok(png_bytes) => {
            let handle = iced::widget::image::Handle::from_bytes(png_bytes);
            container(
                img_widget(handle)
                    .width(Length::Fixed(320.0))
                    .height(Length::Fixed(320.0)),
            )
            .padding(SPACE_SM)
            .style(|theme: &iced::Theme| {
                let p = theme::palette(theme);
                iced::widget::container::Style {
                    background: Some(iced::Background::Color(iced::Color::WHITE)),
                    border: iced::Border {
                        color: p.border,
                        width: 1.0,
                        radius: RADIUS_CONTROL.into(),
                    },
                    ..Default::default()
                }
            })
            .into()
        }
        Err(e) => column![
            theme::status_pill("QR unavailable", StatusKind::Error),
            Space::new().height(Length::Fixed(SPACE_XS)),
            theme::muted(format!("{e}")),
        ]
        .spacing(SPACE_XS)
        .align_x(Alignment::Center)
        .into(),
    };

    let qr_col = column![
        theme::muted("Scan with WireGuard mobile app."),
        Space::new().height(Length::Fixed(SPACE_SM)),
        qr_element,
    ]
    .spacing(0)
    .align_x(Alignment::Center);

    // ── Assemble card ─────────────────────────────────────────────────────────
    let card_inner = column![
        heading,
        Space::new().height(Length::Fixed(SPACE_MD)),
        row![
            conf_col,
            Space::new().width(Length::Fixed(SPACE_LG)),
            qr_col,
        ]
        .align_y(Alignment::Start),
    ]
    .spacing(0);

    column![
        Space::new().height(Length::Fixed(SPACE_LG)),
        container(card_inner)
            .padding(CARD_PADDING)
            .width(Length::Fill)
            .style(|theme: &iced::Theme| {
                let p = theme::palette(theme);
                // Accent-tinted card to make the QR hand-out panel stand out.
                iced::widget::container::Style {
                    text_color: Some(p.text),
                    background: Some(iced::Background::Color(p.surface)),
                    border: iced::Border {
                        color: iced::Color { a: 0.5, ..p.accent },
                        width: 1.5,
                        radius: RADIUS_CARD.into(),
                    },
                    shadow: iced::Shadow {
                        color: iced::Color { a: 0.25, ..iced::Color::BLACK },
                        offset: iced::Vector::new(0.0, 2.0),
                        blur_radius: 16.0,
                    },
                    snap: false,
                }
            }),
    ]
    .spacing(0)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout / formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A two-column info row: muted label on the left (fixed width), body text on the right.
fn info_row(label: &str, value: String) -> Element<'_, Message> {
    row![
        text(label)
            .size(TEXT_CAPTION)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::palette(theme).muted),
            })
            .width(Length::Fixed(110.0)),
        text(value).size(TEXT_BODY),
    ]
    .spacing(SPACE_SM)
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

/// Format a byte count as KiB / MiB / GiB.
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
