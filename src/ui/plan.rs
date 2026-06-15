//! Dry-run plan preview screen — shows what connecting a profile would do.
//!
//! Uses [`crate::ui::theme`] card surfaces and helpers throughout so the
//! preview is visually cohesive with every other screen. All colours, spacing,
//! and text sizes come from the shared palette; no inline literals appear here.

use iced::widget::{button, column, container, row, scrollable, space, text, Space};
use iced::{Alignment, Background, Border, Element, Length, Padding, Theme};

use crate::app::{Message, State};
use crate::ui::theme::{
    self, card_style, icons, muted, section_title, status_pill, title,
    StatusKind, CARD_PADDING, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL,
    SPACE_XS, TEXT_BODY, TEXT_CAPTION, TEXT_SECTION,
};
use crate::wg::plan::DryRunPlan;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the dry-run plan preview for `state.dry_run_plan`.
pub fn plan_preview(state: &State) -> Element<'_, Message> {
    match &state.dry_run_plan {
        Some(plan) => render_plan(plan),
        None => render_empty(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// No-plan fallback (should not normally be visible)
// ─────────────────────────────────────────────────────────────────────────────

fn render_empty() -> Element<'static, Message> {
    container(
        column![
            muted("No plan to preview."),
            button(
                row![
                    text(icons::BACK).size(TEXT_BODY),
                    text("Back").size(TEXT_BODY),
                ]
                .spacing(SPACE_XS)
                .align_y(Alignment::Center),
            )
            .on_press(Message::GoHome)
            .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
            .style(theme::ghost()),
        ]
        .spacing(SPACE_MD),
    )
    .padding(SPACE_XL)
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|theme: &Theme| container::Style {
        background: Some(Background::Color(theme::palette(theme).bg)),
        ..container::Style::default()
    })
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Full plan render
// ─────────────────────────────────────────────────────────────────────────────

fn render_plan<'a>(plan: &'a DryRunPlan) -> Element<'a, Message> {
    // ── Header bar ─────────────────────────────────────────────────────────
    let back_btn = button(
        row![
            text(icons::BACK).size(TEXT_BODY),
            text("Back").size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::GoHome)
    .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
    .style(theme::ghost());

    let header_bar = container(
        row![
            back_btn,
            Space::new().width(SPACE_MD),
            column![
                row![
                    text(icons::SHIELD).size(TEXT_SECTION),
                    title(&plan.profile_name),
                ]
                .spacing(SPACE_SM)
                .align_y(Alignment::Center),
                muted("Connection preview \u{2014} no changes have been made yet."),
            ]
            .spacing(SPACE_XS),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([SPACE_MD as u16, SPACE_LG as u16]))
    .width(Length::Fill)
    .style(|theme: &Theme| {
        let p = theme::palette(theme);
        container::Style {
            background: Some(Background::Color(p.surface)),
            border: Border {
                color: p.border,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..container::Style::default()
        }
    });

    // ── Tunnel mode + status pills row ─────────────────────────────────────
    let tunnel_badge: Element<'_, Message> = if plan.is_full_tunnel {
        tunnel_mode_pill("Full Tunnel", true)
    } else {
        tunnel_mode_pill("Split Tunnel", false)
    };

    let ks_pill: Element<'_, Message> = if plan.kill_switch {
        status_pill("\u{1F512}  Kill switch ON", StatusKind::Error)
    } else {
        status_pill("\u{1F513}  Kill switch off", StatusKind::Idle)
    };

    let badges = row![tunnel_badge, ks_pill,]
        .spacing(SPACE_SM)
        .align_y(Alignment::Center);

    // ── Network details card ────────────────────────────────────────────────
    let addresses_value = if plan.addresses.is_empty() {
        "\u{2014}".to_owned()
    } else {
        plan.addresses.join(",  ")
    };

    let routed_value = if plan.routed_networks.is_empty() {
        "\u{2014}  (no AllowedIPs configured)".to_owned()
    } else {
        plan.routed_networks.join(",  ")
    };

    let dns_value = if plan.dns_servers.is_empty() {
        "\u{2014}  (system default)".to_owned()
    } else {
        plan.dns_servers.join(",  ")
    };

    let endpoint_value = plan
        .endpoint
        .clone()
        .unwrap_or_else(|| "\u{2014}  (no endpoint configured)".to_owned());

    let mtu_value = plan
        .estimated_mtu
        .map(|m| m.to_string())
        .unwrap_or_else(|| "default (1420)".to_owned());

    let peer_value = match plan.peer_count {
        0 => "0  (no peers configured)".to_owned(),
        1 => "1 peer".to_owned(),
        n => format!("{n} peers"),
    };

    let network_details = column![
        detail_row("\u{1F310}  Interface address", addresses_value),
        card_divider(),
        detail_row("\u{2192}  Routed networks (AllowedIPs)", routed_value),
        card_divider(),
        detail_row("\u{1F4E1}  DNS servers", dns_value),
        card_divider(),
        detail_row("\u{1F5A5}  Endpoint", endpoint_value),
        card_divider(),
        detail_row("\u{2194}  MTU", mtu_value),
        card_divider(),
        detail_row("\u{1F465}  Peers", peer_value),
    ]
    .spacing(0)
    .width(Length::Fill);

    let network_card = column![
        section_title("Network"),
        container(network_details)
            .padding(0)
            .width(Length::Fill)
            .style(card_style),
    ]
    .spacing(SPACE_SM)
    .width(Length::Fill);

    // ── Action buttons ──────────────────────────────────────────────────────
    let profile_name = plan.profile_name.clone();
    let connect_btn = button(
        row![
            text(icons::POWER).size(TEXT_BODY),
            text(format!("Connect  \"{}\"", plan.profile_name)).size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::ConnectProfile(profile_name))
    .padding(Padding::from([SPACE_SM as u16, SPACE_LG as u16]))
    .style(theme::success());

    let actions = row![
        space::horizontal(),
        connect_btn,
    ]
    .align_y(Alignment::Center);

    // ── Scroll body ─────────────────────────────────────────────────────────
    let body_col = column![
        badges,
        network_card,
        actions,
    ]
    .spacing(SPACE_MD)
    .padding(Padding::from([SPACE_LG as u16, SPACE_XL as u16]))
    .width(Length::Fill);

    let scrolled = scrollable(body_col).height(Length::Fill);

    container(
        column![header_bar, scrolled].spacing(0),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|theme: &Theme| container::Style {
        background: Some(Background::Color(theme::palette(theme).bg)),
        ..container::Style::default()
    })
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A thin horizontal divider between card rows.
fn card_divider<'a>() -> Element<'a, Message> {
    container(text("").size(1))
        .width(Length::Fill)
        .height(1u32)
        .style(|theme: &Theme| {
            let p = theme::palette(theme);
            container::Style {
                background: Some(Background::Color(p.border)),
                ..container::Style::default()
            }
        })
        .into()
}

/// A detail row inside the network card: label on the left, value on the right.
fn detail_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(
        row![
            text(label).size(TEXT_CAPTION).style(|theme: &Theme| {
                iced::widget::text::Style {
                    color: Some(theme::palette(theme).muted),
                }
            })
            .width(Length::Fixed(240.0)),
            text(value).size(TEXT_BODY).style(|theme: &Theme| {
                iced::widget::text::Style {
                    color: Some(theme::palette(theme).text),
                }
            })
            .width(Length::Fill),
        ]
        .spacing(SPACE_MD)
        .align_y(Alignment::Start),
    )
    .padding(Padding::from([SPACE_MD as u16, CARD_PADDING as u16]))
    .width(Length::Fill)
    .into()
}

/// A pill badge for the tunnel mode (full vs split), themed with accent/warning colours.
fn tunnel_mode_pill<'a>(label: &'a str, is_full: bool) -> Element<'a, Message> {
    let kind = if is_full { StatusKind::Connecting } else { StatusKind::Connected };
    status_pill(label, kind)
}
