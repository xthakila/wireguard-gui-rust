//! Profile list screen — the main landing view showing all saved WireGuard profiles.
//!
//! Layout (top → bottom):
//!   1. Optional banner notification (dismissable)
//!   2. Tunnel status bar (current connection + public IP)
//!   3. Toolbar: search input, sort toggle, import button, new-profile button, settings cog
//!   4. Scrollable profile rows (active pinned first, filtered + sorted)

use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Alignment, Color, Element, Length};

use crate::app::{BannerKind, Message, SortOrder, State, TunnelStatus};

// ─────────────────────────────────────────────────────────────────────────────
// Palette helpers — small, inline, no external dep
// ─────────────────────────────────────────────────────────────────────────────

/// Green used for the "connected" dot and the status badge.
const COLOR_CONNECTED: Color = Color::from_rgb(0.18, 0.80, 0.44);
/// Amber for connecting / disconnecting.
const COLOR_CONNECTING: Color = Color::from_rgb(0.94, 0.69, 0.13);
/// Red for error state.
const COLOR_ERROR: Color = Color::from_rgb(0.90, 0.22, 0.21);
/// Subdued grey for a disconnected dot.
const COLOR_DISCONNECTED: Color = Color::from_rgb(0.45, 0.45, 0.50);

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
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

fn maybe_banner(state: &State) -> Element<'_, Message> {
    match &state.banner {
        None => column![].into(),
        Some(banner) => {
            let bg = match banner.kind {
                BannerKind::Info => Color::from_rgb(0.13, 0.45, 0.83),
                BannerKind::Success => Color::from_rgb(0.10, 0.55, 0.30),
                BannerKind::Warning => Color::from_rgb(0.72, 0.45, 0.0),
                BannerKind::Error => Color::from_rgb(0.75, 0.12, 0.12),
            };

            let dismiss = button(text("  x  ").size(13))
                .on_press(Message::DismissBanner)
                .style(move |_theme, status| {
                    let base = iced::widget::button::Style {
                        background: Some(iced::Background::Color(bg)),
                        text_color: Color::WHITE,
                        border: iced::Border::default(),
                        shadow: iced::Shadow::default(),
                        snap: false,
                    };
                    match status {
                        iced::widget::button::Status::Hovered => iced::widget::button::Style {
                            background: Some(iced::Background::Color(Color {
                                a: 0.85,
                                ..bg
                            })),
                            ..base
                        },
                        _ => base,
                    }
                });

            let label = text(&banner.message)
                .size(14)
                .color(Color::WHITE);

            let inner = row![label, iced::widget::Space::new().width(Length::Fill), dismiss]
                .align_y(Alignment::Center)
                .spacing(8)
                .padding(10);

            container(inner)
                .width(Length::Fill)
                .style(move |_theme| iced::widget::container::Style {
                    background: Some(iced::Background::Color(bg)),
                    ..Default::default()
                })
                .into()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Status bar
// ─────────────────────────────────────────────────────────────────────────────

fn status_bar(state: &State) -> Element<'_, Message> {
    let (status_text, dot_color) = match &state.tunnel_status {
        TunnelStatus::Disconnected => ("Disconnected".to_owned(), COLOR_DISCONNECTED),
        TunnelStatus::Connecting(name) => (format!("Connecting — {name}"), COLOR_CONNECTING),
        TunnelStatus::Connected(name) => (format!("Connected — {name}"), COLOR_CONNECTED),
        TunnelStatus::Disconnecting => ("Disconnecting…".to_owned(), COLOR_CONNECTING),
        TunnelStatus::Error(msg) => (format!("Error: {msg}"), COLOR_ERROR),
    };

    // Colored status dot via a styled container holding a space.
    let dot = container(iced::widget::Space::new().width(10.0_f32).height(10.0_f32))
        .style(move |_theme| iced::widget::container::Style {
            background: Some(iced::Background::Color(dot_color)),
            border: iced::Border {
                radius: 5.0.into(),
                ..Default::default()
            },
            ..Default::default()
        });

    let status_label = text(status_text).size(13);

    // Public IP chip on the right.
    let ip_section: Element<'_, Message> = match &state.public_ip {
        Some(ip) => {
            let ip_text = format!("IP: {ip}");
            text(ip_text).size(13).color(COLOR_CONNECTED).into()
        }
        None if state.public_ip_loading => text("Fetching IP…").size(13).color(COLOR_CONNECTING).into(),
        None => text("").size(13).into(),
    };

    // Connect / disconnect action button in the status bar.
    let action_btn: Element<'_, Message> = match &state.tunnel_status {
        TunnelStatus::Connected(_) | TunnelStatus::Connecting(_) => {
            button(text("Disconnect").size(13))
                .on_press(Message::DisconnectCurrent)
                .into()
        }
        TunnelStatus::Disconnecting => {
            button(text("Disconnecting…").size(13)).into()
        }
        TunnelStatus::Disconnected | TunnelStatus::Error(_) => {
            // Only show a connect button if there is an active/last-used profile.
            match &state.active_profile {
                Some(name) => {
                    let name = name.clone();
                    button(text(format!("Reconnect {name}")).size(13))
                        .on_press(Message::ConnectProfile(name))
                        .into()
                }
                None => iced::widget::Space::new().into(),
            }
        }
    };

    let bar = row![
        dot,
        status_label,
        iced::widget::Space::new().width(Length::Fill),
        ip_section,
        action_btn,
    ]
    .align_y(Alignment::Center)
    .spacing(8)
    .padding([8, 16]);

    container(bar)
        .width(Length::Fill)
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(palette.background.weak.color)),
                border: iced::Border {
                    width: 0.0,
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolbar: search + sort + import + new + settings
// ─────────────────────────────────────────────────────────────────────────────

fn toolbar(state: &State) -> Element<'_, Message> {
    // Search input.
    let search = text_input("Search profiles…", &state.search_query)
        .on_input(Message::SearchChanged)
        .width(Length::FillPortion(3))
        .padding(8);

    // Sort toggle button.
    let (sort_label, next_sort) = match state.sort_order {
        SortOrder::NameAsc => ("Name A→Z", SortOrder::NameDesc),
        SortOrder::NameDesc => ("Name Z→A", SortOrder::NameAsc),
    };
    let sort_btn = button(text(sort_label).size(13))
        .on_press(Message::SortChanged(next_sort))
        .padding([8, 12]);

    // Import button.
    let import_btn = button(text("Import").size(13))
        .on_press(Message::ImportProfile)
        .padding([8, 12]);

    // New profile button (primary action).
    let new_btn = button(text("+ New Profile").size(13))
        .on_press(Message::OpenNewProfile)
        .padding([8, 14]);

    // Settings cog.
    let settings_btn = button(text("Settings").size(13))
        .on_press(Message::OpenSettings)
        .padding([8, 12]);

    let bar = row![
        search,
        sort_btn,
        import_btn,
        new_btn,
        settings_btn,
    ]
    .align_y(Alignment::Center)
    .spacing(8)
    .padding([10, 16]);

    container(bar)
        .width(Length::Fill)
        .style(|theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(palette.background.strong.color)),
                ..Default::default()
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile list rows
// ─────────────────────────────────────────────────────────────────────────────

fn profile_rows(state: &State) -> Element<'_, Message> {
    let query = state.search_query.to_lowercase();

    // Collect profiles filtered by search query.
    let filtered: Vec<&crate::config::profile::WgProfile> = state
        .profiles
        .iter()
        .filter(|p| query.is_empty() || p.name.to_lowercase().contains(&query))
        .collect();

    if filtered.is_empty() {
        let msg = if state.profiles.is_empty() {
            "No profiles yet — click \"+ New Profile\" or \"Import\" to get started."
        } else {
            "No profiles match the search query."
        };

        let empty = container(
            text(msg)
                .size(15)
                .color(COLOR_DISCONNECTED),
        )
        .width(Length::Fill)
        .padding([48, 32])
        .align_x(iced::alignment::Horizontal::Center);

        return scrollable(empty).into();
    }

    // Pin the active profile first, then sort the rest according to sort_order.
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

    // Sort the non-active profiles according to the current sort order.
    // The profiles Vec on State is already sorted by `apply_sort`, but we
    // re-sort the filtered subset here to be safe after the filter pass.
    match state.sort_order {
        SortOrder::NameAsc => rest.sort_by(|a, b| a.name.cmp(&b.name)),
        SortOrder::NameDesc => rest.sort_by(|a, b| b.name.cmp(&a.name)),
    }

    pinned.extend(rest);
    let ordered = pinned;

    let rows: Vec<Element<'_, Message>> = ordered
        .iter()
        .enumerate()
        .map(|(idx, profile)| profile_row(state, profile, idx))
        .collect();

    let list = column(rows).spacing(1).width(Length::Fill);

    scrollable(list)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Render a single profile row.
fn profile_row<'a>(
    state: &'a State,
    profile: &'a crate::config::profile::WgProfile,
    _idx: usize,
) -> Element<'a, Message> {
    let name = &profile.name;
    let is_active = state.active_profile.as_deref() == Some(name.as_str());

    // ── Colored dot ──────────────────────────────────────────────────────────
    let dot_color = if is_active {
        match &state.tunnel_status {
            TunnelStatus::Connected(_) => COLOR_CONNECTED,
            TunnelStatus::Connecting(_) => COLOR_CONNECTING,
            TunnelStatus::Disconnecting => COLOR_CONNECTING,
            TunnelStatus::Error(_) => COLOR_ERROR,
            TunnelStatus::Disconnected => COLOR_DISCONNECTED,
        }
    } else {
        COLOR_DISCONNECTED
    };

    let dot = container(iced::widget::Space::new().width(10.0_f32).height(10.0_f32))
        .style(move |_theme| iced::widget::container::Style {
            background: Some(iced::Background::Color(dot_color)),
            border: iced::Border {
                radius: 5.0.into(),
                ..Default::default()
            },
            ..Default::default()
        });

    // ── Profile name (and optional endpoint summary) ──────────────────────────
    let main_label = text(name.as_str()).size(15);

    // Show the first peer's endpoint as a subtitle if available.
    let subtitle: Element<'a, Message> = profile
        .peers
        .first()
        .and_then(|p| p.endpoint.as_deref())
        .map(|ep| {
            text(ep)
                .size(12)
                .color(Color::from_rgb(0.55, 0.55, 0.60))
                .into()
        })
        .unwrap_or_else(|| iced::widget::Space::new().into());

    let name_col = column![main_label, subtitle].spacing(2);

    // ── Connect button (greyed out if this is already the active tunnel) ──────
    let connect_btn: Element<'a, Message> = if is_active
        && matches!(
            &state.tunnel_status,
            TunnelStatus::Connected(_) | TunnelStatus::Connecting(_)
        ) {
        // Already active — show a disconnect button instead.
        button(text("Disconnect").size(12))
            .on_press(Message::DisconnectCurrent)
            .padding([5, 10])
            .into()
    } else {
        let n = name.clone();
        button(text("Connect").size(12))
            .on_press(Message::ConnectProfile(n))
            .padding([5, 10])
            .into()
    };

    // ── Edit ──────────────────────────────────────────────────────────────────
    let n = name.clone();
    let edit_btn = button(text("Edit").size(12))
        .on_press(Message::EditProfile(n))
        .padding([5, 10]);

    // ── Export ───────────────────────────────────────────────────────────────
    let n = name.clone();
    let export_btn = button(text("Export").size(12))
        .on_press(Message::ExportProfile(n))
        .padding([5, 10]);

    // ── Delete ───────────────────────────────────────────────────────────────
    let n = name.clone();
    let delete_btn = button(text("Delete").size(12))
        .on_press(Message::DeleteProfile(n))
        .padding([5, 10])
        .style(|_theme, status| {
            let base_bg = Color::from_rgb(0.55, 0.10, 0.10);
            let hover_bg = Color::from_rgb(0.72, 0.13, 0.13);
            let bg = match status {
                iced::widget::button::Status::Hovered => hover_bg,
                _ => base_bg,
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

    // ── Peer count badge ──────────────────────────────────────────────────────
    let peer_count = profile.peers.len();
    let badge_label = if peer_count == 1 {
        "1 peer".to_owned()
    } else {
        format!("{peer_count} peers")
    };
    let badge = text(badge_label)
        .size(11)
        .color(Color::from_rgb(0.55, 0.55, 0.60));

    // ── Full row ──────────────────────────────────────────────────────────────
    let inner = row![
        dot,
        name_col,
        iced::widget::Space::new().width(Length::Fill),
        badge,
        connect_btn,
        edit_btn,
        export_btn,
        delete_btn,
    ]
    .align_y(Alignment::Center)
    .spacing(10)
    .padding([10, 16]);

    // Highlight the active row with a slightly distinct background.
    let row_bg = if is_active {
        |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(
                    palette.primary.weak.color,
                )),
                border: iced::Border {
                    width: 0.0,
                    radius: 6.0.into(),
                    color: Color::TRANSPARENT,
                },
                ..Default::default()
            }
        }
    } else {
        |theme: &iced::Theme| {
            let palette = theme.extended_palette();
            iced::widget::container::Style {
                background: Some(iced::Background::Color(
                    palette.background.base.color,
                )),
                border: iced::Border {
                    width: 0.0,
                    radius: 6.0.into(),
                    color: Color::TRANSPARENT,
                },
                ..Default::default()
            }
        }
    };

    container(inner)
        .width(Length::Fill)
        .style(row_bg)
        .into()
}
