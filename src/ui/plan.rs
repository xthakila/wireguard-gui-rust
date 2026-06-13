//! Dry-run plan preview screen — shows what connecting a profile would do,
//! with a Back button (GoHome) and a Connect button (ConnectProfile).

use iced::widget::{
    button, column, container, row, rule, scrollable, space, text, Space,
};
use iced::{Alignment, Element, Length};

use crate::app::{Message, State};
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
// No plan case (should not normally be visible, but guard it cleanly)
// ─────────────────────────────────────────────────────────────────────────────

fn render_empty() -> Element<'static, Message> {
    container(
        column![
            text("No plan to preview.").size(16),
            button("Back").on_press(Message::GoHome),
        ]
        .spacing(12),
    )
    .padding(24)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Full plan render
// ─────────────────────────────────────────────────────────────────────────────

fn render_plan<'a>(plan: &'a DryRunPlan) -> Element<'a, Message> {
    // ── Header ──────────────────────────────────────────────────────────────
    let header = column![
        text(&plan.profile_name).size(24),
        text("Connection preview — no changes have been made yet.")
            .size(13)
            .style(text::secondary),
    ]
    .spacing(4);

    // ── Tunnel mode badge ────────────────────────────────────────────────────
    let tunnel_badge = if plan.is_full_tunnel {
        container(text("Full Tunnel  (all traffic routed)").size(13))
            .padding([4, 10])
            .style(container::rounded_box)
    } else {
        container(text("Split Tunnel  (selected networks only)").size(13))
            .padding([4, 10])
            .style(container::rounded_box)
    };

    // ── Detail rows ──────────────────────────────────────────────────────────

    // Interface addresses
    let addresses_value = if plan.addresses.is_empty() {
        "\u{2014}".to_owned()
    } else {
        plan.addresses.join(",  ")
    };

    // Routed networks (AllowedIPs)
    let routed_value = if plan.routed_networks.is_empty() {
        "\u{2014}  (no AllowedIPs configured)".to_owned()
    } else {
        plan.routed_networks.join(",  ")
    };

    // DNS
    let dns_value = if plan.dns_servers.is_empty() {
        "\u{2014}  (system default)".to_owned()
    } else {
        plan.dns_servers.join(",  ")
    };

    // Endpoint
    let endpoint_value = plan
        .endpoint
        .clone()
        .unwrap_or_else(|| "\u{2014}  (no endpoint configured)".to_owned());

    // MTU
    let mtu_value = plan
        .estimated_mtu
        .map(|m| m.to_string())
        .unwrap_or_else(|| "default (1420)".to_owned());

    // Kill switch
    let ks_value = if plan.kill_switch {
        "Enabled  \u{2014} traffic blocked when tunnel is down".to_owned()
    } else {
        "Disabled".to_owned()
    };

    // Peer count
    let peer_value = match plan.peer_count {
        0 => "0  (no peers configured)".to_owned(),
        1 => "1 peer".to_owned(),
        n => format!("{n} peers"),
    };

    // Build the detail section
    let details = column![
        detail_row("Interface address", addresses_value),
        detail_row("Routed networks (AllowedIPs)", routed_value),
        detail_row("DNS servers", dns_value),
        detail_row("Endpoint", endpoint_value),
        detail_row("MTU", mtu_value),
        detail_row("Kill switch", ks_value),
        detail_row("Peer count", peer_value),
    ]
    .spacing(0); // rows carry their own vertical padding

    // ── Action buttons ───────────────────────────────────────────────────────
    let profile_name = plan.profile_name.clone();
    let actions = row![
        button("Back").on_press(Message::GoHome),
        space::horizontal(),
        button(
            text(format!("Connect  \"{}\"", plan.profile_name)).size(14),
        )
        .on_press(Message::ConnectProfile(profile_name))
        .style(button::primary),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    // ── Outer layout ─────────────────────────────────────────────────────────
    let content = column![
        header,
        Space::new().height(Length::Fixed(4.0)),
        tunnel_badge,
        Space::new().height(Length::Fixed(8.0)),
        rule::horizontal(1),
        Space::new().height(Length::Fixed(8.0)),
        scrollable(details).height(Length::Fill),
        rule::horizontal(1),
        Space::new().height(Length::Fixed(8.0)),
        actions,
    ]
    .spacing(0)
    .padding(24)
    .width(Length::Fill)
    .height(Length::Fill);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: a labeled detail row (label left, value right)
// ─────────────────────────────────────────────────────────────────────────────

fn detail_row<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(
        row![
            text(label)
                .size(13)
                .style(text::secondary)
                .width(Length::Fixed(220.0)),
            text(value).size(13).width(Length::Fill),
        ]
        .spacing(12)
        .align_y(Alignment::Start),
    )
    .padding([6, 0])
    .width(Length::Fill)
    .into()
}
