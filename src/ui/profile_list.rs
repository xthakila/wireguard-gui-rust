//! Profile list screen — the main landing view showing all saved WireGuard profiles.
//!
//! Visual design: every profile is a card row (subtle elevation + hairline border)
//! with a coloured status dot, a two-line name/subtitle block, a right-aligned row
//! of icon buttons, and a status pill on the active card.  The toolbar has a
//! search input with inline icon, a sort toggle, and icon buttons for import / new /
//! server / settings.  An illustrated empty state guides the user when no profiles
//! exist.
//!
//! All colours, spacing, radii, and button styles come from [`crate::ui::theme`]
//! so the screen is visually cohesive with the rest of the app.

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Background, Border, Color, Element, Length, Shadow, Vector};

use crate::app::{BannerKind, Message, SortOrder, State, TunnelStatus};
use crate::ui::theme::{
    self,
    icons,
    StatusKind,
    CARD_PADDING,
    RADIUS_CARD,
    RADIUS_CONTROL,
    RADIUS_PILL,
    SPACE_MD,
    SPACE_SM,
    SPACE_XL,
    SPACE_XS,
    TEXT_BODY,
    TEXT_CAPTION,
    TEXT_SECTION,
    TEXT_TITLE,
};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the profile list / roster screen.
pub fn profile_list(state: &State) -> Element<'_, Message> {
    let content = column![
        maybe_banner(state),
        status_bar(state),
        toolbar(state),
        profile_rows(state),
    ]
    .spacing(0)
    .width(Length::Fill);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(0)
        .style(|theme: &iced::Theme| {
            let p = theme::palette(theme);
            iced::widget::container::Style {
                background: Some(Background::Color(p.bg)),
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

fn maybe_banner(state: &State) -> Element<'_, Message> {
    let Some(banner) = &state.banner else {
        return column![].into();
    };

    let (status_kind, icon_glyph): (StatusKind, &str) = match banner.kind {
        BannerKind::Info => (StatusKind::Connecting, icons::SHIELD),
        BannerKind::Success => (StatusKind::Connected, icons::LOCK),
        BannerKind::Warning => (StatusKind::Connecting, icons::REFRESH),
        BannerKind::Error => (StatusKind::Error, icons::STOP),
    };

    let icon_el = text(icon_glyph)
        .size(TEXT_BODY)
        .style(move |theme: &iced::Theme| iced::widget::text::Style {
            color: Some(status_kind.color(theme)),
        });

    let label = text(&banner.message)
        .size(TEXT_BODY)
        .style(move |theme: &iced::Theme| iced::widget::text::Style {
            color: Some(status_kind.color(theme)),
        });

    let dismiss = button(text(icons::STOP).size(TEXT_CAPTION))
        .on_press(Message::DismissBanner)
        .padding([SPACE_XS, SPACE_SM])
        .style(move |theme: &iced::Theme, status: iced::widget::button::Status| {
            let p = theme::palette(theme);
            let bg = match status {
                iced::widget::button::Status::Hovered
                | iced::widget::button::Status::Pressed => {
                    Some(Background::Color(p.surface_alt))
                }
                _ => None,
            };
            iced::widget::button::Style {
                background: bg,
                text_color: status_kind.color(theme),
                border: Border {
                    radius: RADIUS_CONTROL.into(),
                    ..Border::default()
                },
                shadow: Shadow::default(),
                snap: false,
            }
        });

    let inner = row![
        icon_el,
        label,
        iced::widget::Space::new().width(Length::Fill),
        dismiss
    ]
    .align_y(Alignment::Center)
    .spacing(SPACE_SM)
    .padding([SPACE_SM, SPACE_MD]);

    container(inner)
        .width(Length::Fill)
        .style(move |theme: &iced::Theme| {
            let p = theme::palette(theme);
            let c = status_kind.color(theme);
            iced::widget::container::Style {
                background: Some(Background::Color(Color { a: 0.12, ..c })),
                border: Border {
                    color: Color { a: 0.30, ..c },
                    width: 0.0,
                    radius: 0.0.into(),
                },
                text_color: Some(p.text),
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Status bar — tunnel status pill + public IP chip + connect/disconnect button
// ─────────────────────────────────────────────────────────────────────────────

fn status_bar(state: &State) -> Element<'_, Message> {
    let (status_text, kind): (&str, StatusKind) = match &state.tunnel_status {
        TunnelStatus::Disconnected => ("Disconnected", StatusKind::Idle),
        TunnelStatus::Connecting(_) => ("Connecting…", StatusKind::Connecting),
        TunnelStatus::Connected(_) => ("Connected", StatusKind::Connected),
        TunnelStatus::Disconnecting => ("Disconnecting…", StatusKind::Connecting),
        TunnelStatus::Error(_) => ("Error", StatusKind::Error),
    };

    // Subtitle below the status text (profile name or error message).
    let subtitle: Option<String> = match &state.tunnel_status {
        TunnelStatus::Connected(name) | TunnelStatus::Connecting(name) => Some(name.clone()),
        TunnelStatus::Error(msg) => Some(msg.clone()),
        _ => None,
    };

    let pill = theme::status_pill(status_text, kind);

    let subtitle_el: Element<'_, Message> = match subtitle {
        Some(s) => theme::muted(s).into(),
        None => iced::widget::Space::new().width(0).height(0).into(),
    };

    let shield_icon = text(icons::LOCK)
        .size(TEXT_TITLE)
        .style(move |theme: &iced::Theme| iced::widget::text::Style {
            color: Some(kind.color(theme)),
        });

    // Public IP chip.
    let ip_el: Element<'_, Message> = match &state.public_ip {
        Some(ip) => {
            let chip_text = format!("{} {ip}", icons::SERVER);
            container(
                text(chip_text)
                    .size(TEXT_CAPTION)
                    .style(|theme: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme::palette(theme).muted),
                    }),
            )
            .padding([SPACE_XS, SPACE_SM])
            .style(|theme: &iced::Theme| {
                let p = theme::palette(theme);
                iced::widget::container::Style {
                    background: Some(Background::Color(p.surface_alt)),
                    border: Border {
                        color: p.border,
                        width: 1.0,
                        radius: RADIUS_PILL.into(),
                    },
                    ..Default::default()
                }
            })
            .into()
        }
        None if state.public_ip_loading => theme::muted("Fetching IP…").into(),
        None => iced::widget::Space::new().width(0).height(0).into(),
    };

    // Action button (connect / disconnect).
    let action_btn: Element<'_, Message> = match &state.tunnel_status {
        TunnelStatus::Connected(_) | TunnelStatus::Connecting(_) => {
            let label = row![
                text(icons::STOP).size(TEXT_BODY),
                text("Disconnect").size(TEXT_BODY),
            ]
            .spacing(SPACE_XS)
            .align_y(Alignment::Center);
            button(label)
                .on_press(Message::DisconnectCurrent)
                .padding([SPACE_XS + 2.0, SPACE_MD])
                .style(theme::danger())
                .into()
        }
        TunnelStatus::Disconnecting => {
            let label = text("Disconnecting…").size(TEXT_BODY);
            button(label)
                .padding([SPACE_XS + 2.0, SPACE_MD])
                .style(theme::ghost())
                .into()
        }
        TunnelStatus::Disconnected | TunnelStatus::Error(_) => {
            match &state.active_profile {
                Some(name) => {
                    let name = name.clone();
                    let label = row![
                        text(icons::POWER).size(TEXT_BODY),
                        text(format!("Reconnect {name}")).size(TEXT_BODY),
                    ]
                    .spacing(SPACE_XS)
                    .align_y(Alignment::Center);
                    button(label)
                        .on_press(Message::ConnectProfile(name))
                        .padding([SPACE_XS + 2.0, SPACE_MD])
                        .style(theme::primary())
                        .into()
                }
                None => iced::widget::Space::new().width(0).into(),
            }
        }
    };

    let status_col = column![
        row![shield_icon, pill].spacing(SPACE_SM).align_y(Alignment::Center),
        subtitle_el,
    ]
    .spacing(SPACE_XS);

    let bar = row![
        status_col,
        iced::widget::Space::new().width(Length::Fill),
        ip_el,
        action_btn,
    ]
    .align_y(Alignment::Center)
    .spacing(SPACE_MD)
    .padding([SPACE_MD, SPACE_XL]);

    container(bar)
        .width(Length::Fill)
        .style(|theme: &iced::Theme| {
            let p = theme::palette(theme);
            iced::widget::container::Style {
                background: Some(Background::Color(p.surface)),
                border: Border {
                    color: p.border,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolbar: search + sort + import + new + server + settings
// ─────────────────────────────────────────────────────────────────────────────

fn toolbar(state: &State) -> Element<'_, Message> {
    // Search input — styled to match the card border/radius vocabulary.
    let search = text_input(
        &format!("{} Search profiles…", icons::SHIELD),
        &state.search_query,
    )
    .on_input(Message::SearchChanged)
    .width(Length::FillPortion(4))
    .padding([SPACE_SM, SPACE_MD])
    .style(|theme: &iced::Theme, status: iced::widget::text_input::Status| {
        use iced::widget::text_input;
        let p = theme::palette(theme);
        let border_color = match status {
            text_input::Status::Focused { .. } => p.accent,
            _ => p.border,
        };
        text_input::Style {
            background: Background::Color(p.surface_alt),
            border: Border {
                color: border_color,
                width: 1.0,
                radius: RADIUS_CONTROL.into(),
            },
            icon: p.muted,
            placeholder: p.muted,
            value: p.text,
            selection: Color { a: 0.3, ..p.accent },
        }
    });

    // Sort toggle with icon.
    let (sort_label, next_sort) = match state.sort_order {
        SortOrder::NameAsc => (format!("{} A→Z", icons::IMPORT), SortOrder::NameDesc),
        SortOrder::NameDesc => (format!("{} Z→A", icons::EXPORT), SortOrder::NameAsc),
    };
    let sort_btn = button(text(sort_label).size(TEXT_BODY))
        .on_press(Message::SortChanged(next_sort))
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::ghost());

    // Import button.
    let import_label = format!("{} Import", icons::IMPORT);
    let import_btn = button(text(import_label).size(TEXT_BODY))
        .on_press(Message::ImportProfile)
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::ghost());

    // Import from QR image button (feature 4).
    let qr_import_label = format!("{} QR Import", icons::IMPORT);
    let qr_import_btn = button(text(qr_import_label).size(TEXT_BODY))
        .on_press(Message::ImportFromQr)
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::ghost());

    // New profile — primary CTA.
    let new_label = format!("{} New", icons::PLUS);
    let new_btn = button(text(new_label).size(TEXT_BODY))
        .on_press(Message::OpenNewProfile)
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::primary());

    // Server mode button.
    let server_label = format!("{} Server", icons::SERVER);
    let server_btn = button(text(server_label).size(TEXT_BODY))
        .on_press(Message::OpenServer)
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::ghost());

    // Settings cog.
    let settings_label = format!("{} Settings", icons::GEAR);
    let settings_btn = button(text(settings_label).size(TEXT_BODY))
        .on_press(Message::OpenSettings)
        .padding([SPACE_SM, SPACE_MD])
        .style(theme::ghost());

    let bar = row![
        search,
        sort_btn,
        import_btn,
        qr_import_btn,
        new_btn,
        server_btn,
        settings_btn,
    ]
    .align_y(Alignment::Center)
    .spacing(SPACE_SM)
    .padding([SPACE_SM, SPACE_XL]);

    container(bar)
        .width(Length::Fill)
        .style(|theme: &iced::Theme| {
            let p = theme::palette(theme);
            iced::widget::container::Style {
                background: Some(Background::Color(p.bg)),
                border: Border {
                    color: p.border,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile list — card rows or empty state
// ─────────────────────────────────────────────────────────────────────────────

fn profile_rows(state: &State) -> Element<'_, Message> {
    let query = state.search_query.to_lowercase();

    let filtered: Vec<&crate::config::profile::WgProfile> = state
        .profiles
        .iter()
        .filter(|p| query.is_empty() || p.name.to_lowercase().contains(&query))
        .collect();

    if filtered.is_empty() {
        return empty_state(state);
    }

    // Pin the active profile first, rest sorted by current order.
    let active_name = state.active_profile.as_deref().unwrap_or("");

    let mut pinned: Vec<&crate::config::profile::WgProfile> = filtered
        .iter()
        .copied()
        .filter(|p| p.name == active_name)
        .collect();

    let mut rest: Vec<&crate::config::profile::WgProfile> = filtered
        .iter()
        .copied()
        .filter(|p| p.name != active_name)
        .collect();

    match state.sort_order {
        SortOrder::NameAsc => rest.sort_by(|a, b| a.name.cmp(&b.name)),
        SortOrder::NameDesc => rest.sort_by(|a, b| b.name.cmp(&a.name)),
    }
    pinned.extend(rest);
    let ordered = pinned;

    let rows: Vec<Element<'_, Message>> = ordered
        .iter()
        .map(|profile| profile_card(state, profile))
        .collect();

    let list = column(rows)
        .spacing(SPACE_SM)
        .width(Length::Fill)
        .padding([SPACE_MD, SPACE_XL]);

    scrollable(list)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty state — illustrated prompt with New/Import CTAs
// ─────────────────────────────────────────────────────────────────────────────

fn empty_state(state: &State) -> Element<'_, Message> {
    let (heading, sub) = if state.profiles.is_empty() {
        (
            format!("{} No VPN profiles yet", icons::SHIELD),
            "Create a new profile or import an existing .conf file to get started.",
        )
    } else {
        (
            format!("{} No matches", icons::SHIELD),
            "No profiles match your search. Try a different query.",
        )
    };

    let heading_el = text(heading)
        .size(TEXT_SECTION)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme::palette(theme).muted),
        });

    let sub_el = text(sub)
        .size(TEXT_BODY)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme::palette(theme).muted),
        });

    let new_label = format!("{} New Profile", icons::PLUS);
    let new_btn = button(text(new_label).size(TEXT_BODY))
        .on_press(Message::OpenNewProfile)
        .padding([SPACE_SM, SPACE_XL])
        .style(theme::primary());

    let import_label = format!("{} Import .conf", icons::IMPORT);
    let import_btn = button(text(import_label).size(TEXT_BODY))
        .on_press(Message::ImportProfile)
        .padding([SPACE_SM, SPACE_XL])
        .style(theme::ghost());

    let actions = row![new_btn, import_btn]
        .spacing(SPACE_MD)
        .align_y(Alignment::Center);

    let inner = column![heading_el, sub_el, actions]
        .spacing(SPACE_MD)
        .align_x(iced::alignment::Horizontal::Center);

    container(inner)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(iced::alignment::Horizontal::Center)
        .align_y(iced::alignment::Vertical::Center)
        .padding(SPACE_XL)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual profile card
// ─────────────────────────────────────────────────────────────────────────────

fn profile_card<'a>(
    state: &'a State,
    profile: &'a crate::config::profile::WgProfile,
) -> Element<'a, Message> {
    let name = &profile.name;
    let is_active = state.active_profile.as_deref() == Some(name.as_str());

    // ── Status dot / kind ────────────────────────────────────────────────────
    let kind = if is_active {
        match &state.tunnel_status {
            TunnelStatus::Connected(_) => StatusKind::Connected,
            TunnelStatus::Connecting(_) | TunnelStatus::Disconnecting => StatusKind::Connecting,
            TunnelStatus::Error(_) => StatusKind::Error,
            TunnelStatus::Disconnected => StatusKind::Idle,
        }
    } else {
        StatusKind::Idle
    };

    // Larger dot for the card (12 px feels right at card size).
    let dot = theme::status_dot(kind, 12.0);

    // ── Profile name (two-line: title + muted subtitle) ──────────────────────
    let name_text = text(name.as_str())
        .size(TEXT_BODY)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme::palette(theme).text),
        });

    // Subtitle: endpoint of first peer, or address of the interface, or peer count.
    let subtitle_str: String = profile
        .peers
        .first()
        .and_then(|p| p.endpoint.as_deref())
        .map(|ep| ep.to_owned())
        .or_else(|| {
            profile
                .interface
                .address
                .first()
                .cloned()
        })
        .unwrap_or_else(|| {
            let n = profile.peers.len();
            if n == 1 { "1 peer".to_owned() } else { format!("{n} peers") }
        });

    let subtitle_el = text(subtitle_str)
        .size(TEXT_CAPTION)
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme::palette(theme).muted),
        });

    // Optional total usage subtitle (feature 2): show lifetime rx/tx when available.
    let usage_el: Option<iced::widget::Text<'_, iced::Theme>> =
        state.usage_store.get(name.as_str()).map(|u| {
            text(format!(
                "\u{2193} {}  \u{2191} {} total",
                format_bytes(u.total_rx),
                format_bytes(u.total_tx),
            ))
            .size(TEXT_CAPTION)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::palette(theme).muted),
            })
        });

    let mut name_col = column![name_text, subtitle_el].spacing(SPACE_XS);
    if let Some(usage) = usage_el {
        name_col = name_col.push(usage);
    }

    // ── Right-hand section: status pill (active) + icon buttons ──────────────
    // Status pill — only on the active row.
    let pill_el: Option<Element<'_, Message>> = if is_active {
        let pill_label = match &state.tunnel_status {
            TunnelStatus::Connected(_) => "Connected",
            TunnelStatus::Connecting(_) => "Connecting",
            TunnelStatus::Disconnecting => "Disconnecting",
            TunnelStatus::Error(_) => "Error",
            TunnelStatus::Disconnected => "Idle",
        };
        Some(theme::status_pill(pill_label, kind))
    } else {
        None
    };

    // ── Connect / Disconnect button ──────────────────────────────────────────
    let connect_btn: Element<'_, Message> = if is_active
        && matches!(
            &state.tunnel_status,
            TunnelStatus::Connected(_) | TunnelStatus::Connecting(_)
        ) {
        button(text(icons::STOP).size(TEXT_SECTION))
            .on_press(Message::DisconnectCurrent)
            .padding([SPACE_XS, SPACE_SM])
            .style(theme::danger())
            .into()
    } else {
        let n = name.clone();
        button(text(icons::POWER).size(TEXT_SECTION))
            .on_press(Message::ConnectProfile(n))
            .padding([SPACE_XS, SPACE_SM])
            .style(theme::success())
            .into()
    };

    // ── Edit ─────────────────────────────────────────────────────────────────
    let n_edit = name.clone();
    let edit_btn = button(text(icons::EDIT).size(TEXT_SECTION))
        .on_press(Message::EditProfile(n_edit))
        .padding([SPACE_XS, SPACE_SM])
        .style(theme::icon_button());

    // ── Export ────────────────────────────────────────────────────────────────
    let n_exp = name.clone();
    let export_btn = button(text(icons::EXPORT).size(TEXT_SECTION))
        .on_press(Message::ExportProfile(n_exp))
        .padding([SPACE_XS, SPACE_SM])
        .style(theme::icon_button());

    // ── Delete ────────────────────────────────────────────────────────────────
    let n_del = name.clone();
    let delete_btn = button(text(icons::TRASH).size(TEXT_SECTION))
        .on_press(Message::DeleteProfile(n_del))
        .padding([SPACE_XS, SPACE_SM])
        .style(theme::danger());

    // ── Assemble right section ────────────────────────────────────────────────
    let mut right_items: Vec<Element<'_, Message>> = Vec::new();
    if let Some(pill) = pill_el {
        right_items.push(pill);
    }
    right_items.push(connect_btn);
    right_items.push(edit_btn.into());
    right_items.push(export_btn.into());
    right_items.push(delete_btn.into());

    let right_row = row(right_items)
        .spacing(SPACE_XS)
        .align_y(Alignment::Center);

    // ── Full inner row ────────────────────────────────────────────────────────
    let inner = row![
        dot,
        name_col,
        iced::widget::Space::new().width(Length::Fill),
        right_row,
    ]
    .align_y(Alignment::Center)
    .spacing(SPACE_MD)
    .padding([CARD_PADDING, CARD_PADDING]);

    // ── Card container — elevated for active, standard for inactive ───────────
    container(inner)
        .width(Length::Fill)
        .style(move |theme: &iced::Theme| {
            let p = theme::palette(theme);
            if is_active {
                // Active card: stronger surface + accent left-border hint via shadow.
                let accent = p.accent;
                iced::widget::container::Style {
                    background: Some(Background::Color(p.surface_alt)),
                    border: Border {
                        color: Color { a: 0.55, ..accent },
                        width: 1.0,
                        radius: RADIUS_CARD.into(),
                    },
                    shadow: Shadow {
                        color: Color { a: 0.18, ..accent },
                        offset: Vector::new(0.0, 2.0),
                        blur_radius: 14.0,
                    },
                    text_color: Some(p.text),
                    snap: false,
                }
            } else {
                // Standard card.
                theme::card_style(theme)
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Formatting helpers
// ─────────────────────────────────────────────────────────────────────────────

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
