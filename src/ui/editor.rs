//! Profile editor + raw-text editor screens.
//!
//! `editor` renders the structured form (Interface fields + Peers).
//! `raw_editor` renders a full-height text editor for the raw `.conf` content.
//!
//! The raw editor borrows the persisted [`text_editor::Content`] that lives on
//! the top-level `State` (`state.raw_editor_content`). Holding the `Content`
//! there — and mutating it in place via `perform(action)` in the reducer — keeps
//! the cursor/selection alive across frames, so Backspace/Delete work. The
//! widget takes `&'a Content`; the borrow of `state` supplies that `'a`
//! directly, so no lifetime tricks are needed.

use iced::widget::{
    button, column, container, row, scrollable, text, text_editor, text_input,
};
use iced::{Color, Element, Length, Padding};

use crate::app::{BannerKind, EditorField, EditorState, Message, State};

// ─────────────────────────────────────────────────────────────────────────────
// Colour helpers
// ─────────────────────────────────────────────────────────────────────────────

fn error_color() -> Color {
    Color::from_rgb(0.9, 0.2, 0.2)
}

fn muted_color() -> Color {
    Color::from_rgb(0.55, 0.55, 0.60)
}

fn section_color() -> Color {
    Color::from_rgb(0.5, 0.75, 1.0)
}

fn success_color() -> Color {
    Color::from_rgb(0.2, 0.8, 0.4)
}

fn warning_color() -> Color {
    Color::from_rgb(0.95, 0.75, 0.2)
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────

fn banner_row(state: &State) -> Option<Element<'_, Message>> {
    let b = state.banner.as_ref()?;
    let color = match b.kind {
        BannerKind::Info => muted_color(),
        BannerKind::Success => success_color(),
        BannerKind::Warning => warning_color(),
        BannerKind::Error => error_color(),
    };
    let banner = row![
        text(b.message.clone()).color(color).width(Length::Fill),
        button("✕").on_press(Message::DismissBanner),
    ]
    .spacing(8)
    .padding(Padding::from([6, 12]));

    Some(container(banner).width(Length::Fill).into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation error lookup
// ─────────────────────────────────────────────────────────────────────────────

fn first_error_for<'a>(
    errors: &'a [(String, String)],
    field_prefix: &str,
) -> Option<&'a str> {
    errors
        .iter()
        .find(|(f, _)| f.starts_with(field_prefix))
        .map(|(_, msg)| msg.as_str())
}

fn error_label(msg: &str) -> Element<'_, Message> {
    text(format!("  {msg}"))
        .size(12)
        .color(error_color())
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Labelled field helper
// ─────────────────────────────────────────────────────────────────────────────

/// A row with a fixed-width label on the left and a widget on the right.
fn labelled<'a>(label_text: &'a str, widget: Element<'a, Message>) -> Element<'a, Message> {
    row![
        text(label_text)
            .color(muted_color())
            .width(Length::Fixed(130.0)),
        widget,
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface section
// ─────────────────────────────────────────────────────────────────────────────

fn interface_section<'a>(editor: &'a EditorState) -> Element<'a, Message> {
    let draft = &editor.draft;
    let errors = &editor.validation_errors;

    // Profile name field — disabled when editing an existing profile.
    let name_input: Element<'_, Message> = if editor.is_new {
        text_input("e.g. home-vpn", &editor.profile_name)
            .on_input(|v| Message::EditorFieldChanged(EditorField::ProfileName(v)))
            .padding(6)
            .width(Length::Fill)
            .into()
    } else {
        // Existing profile: name is read-only (no on_input binding).
        text_input("", &editor.profile_name)
            .padding(6)
            .width(Length::Fill)
            .into()
    };

    // PrivateKey row: input + generate button.
    let privkey_row: Element<'_, Message> = row![
        text_input("Base-64 private key", &draft.interface.private_key)
            .on_input(|v| Message::EditorFieldChanged(EditorField::PrivateKey(v)))
            .padding(6)
            .width(Length::Fill),
        button("Generate").on_press(Message::GenerateKeypair),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into();

    let privkey_error = first_error_for(errors, "Interface.PrivateKey");
    let address_error = first_error_for(errors, "Interface.Address");

    let mut iface_col = column![
        text("[Interface]").size(16).color(section_color()),
        labelled("Profile Name", name_input),
        labelled("Private Key", privkey_row),
    ]
    .spacing(10);

    if let Some(msg) = privkey_error {
        iface_col = iface_col.push(error_label(msg));
    }

    iface_col = iface_col.push(labelled(
        "Address",
        text_input(
            "10.0.0.2/24, fd00::2/128",
            &draft.interface.address.join(", "),
        )
        .on_input(|v| Message::EditorFieldChanged(EditorField::Address(v)))
        .padding(6)
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = address_error {
        iface_col = iface_col.push(error_label(msg));
    }

    iface_col = iface_col
        .push(labelled(
            "DNS",
            text_input("1.1.1.1, 8.8.8.8", &draft.interface.dns.join(", "))
                .on_input(|v| Message::EditorFieldChanged(EditorField::Dns(v)))
                .padding(6)
                .width(Length::Fill)
                .into(),
        ))
        .push(labelled(
            "Listen Port",
            text_input(
                "51820",
                &draft
                    .interface
                    .listen_port
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
            )
            .on_input(|v| Message::EditorFieldChanged(EditorField::ListenPort(v)))
            .padding(6)
            .width(Length::Fixed(100.0))
            .into(),
        ))
        .push(labelled(
            "MTU",
            text_input(
                "1420",
                &draft
                    .interface
                    .mtu
                    .map(|m| m.to_string())
                    .unwrap_or_default(),
            )
            .on_input(|v| Message::EditorFieldChanged(EditorField::Mtu(v)))
            .padding(6)
            .width(Length::Fixed(100.0))
            .into(),
        ));

    iface_col.into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer section
// ─────────────────────────────────────────────────────────────────────────────

fn peer_section<'a>(
    peer: &'a crate::config::profile::PeerSection,
    idx: usize,
    errors: &'a [(String, String)],
) -> Element<'a, Message> {
    let pubkey_error = first_error_for(errors, &format!("Peer[{idx}].PublicKey"));
    let psk_error = first_error_for(errors, &format!("Peer[{idx}].PresharedKey"));
    let endpoint_error = first_error_for(errors, &format!("Peer[{idx}].Endpoint"));
    let allowedips_error = first_error_for(errors, &format!("Peer[{idx}].AllowedIPs"));

    let heading_row: Element<'_, Message> = row![
        text(format!("[Peer {}]", idx + 1))
            .size(14)
            .color(section_color())
            .width(Length::Fill),
        button("Remove").on_press(Message::EditorFieldChanged(EditorField::RemovePeer(idx))),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into();

    let mut peer_col = column![heading_row].spacing(8).push(labelled(
        "Public Key",
        text_input("Base-64 public key", &peer.public_key)
            .on_input(move |v| Message::EditorFieldChanged(EditorField::PeerPublicKey(idx, v)))
            .padding(6)
            .width(Length::Fill)
            .into(),
    ));

    if let Some(msg) = pubkey_error {
        peer_col = peer_col.push(error_label(msg));
    }

    peer_col = peer_col.push(labelled(
        "Preshared Key",
        text_input(
            "Optional — base-64 key",
            peer.preshared_key.as_deref().unwrap_or(""),
        )
        .on_input(move |v| Message::EditorFieldChanged(EditorField::PeerPresharedKey(idx, v)))
        .padding(6)
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = psk_error {
        peer_col = peer_col.push(error_label(msg));
    }

    peer_col = peer_col.push(labelled(
        "Endpoint",
        text_input(
            "vpn.example.com:51820",
            peer.endpoint.as_deref().unwrap_or(""),
        )
        .on_input(move |v| Message::EditorFieldChanged(EditorField::PeerEndpoint(idx, v)))
        .padding(6)
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = endpoint_error {
        peer_col = peer_col.push(error_label(msg));
    }

    peer_col = peer_col.push(labelled(
        "Allowed IPs",
        text_input("0.0.0.0/0, ::/0", &peer.allowed_ips.join(", "))
            .on_input(move |v| Message::EditorFieldChanged(EditorField::PeerAllowedIps(idx, v)))
            .padding(6)
            .width(Length::Fill)
            .into(),
    ));

    if let Some(msg) = allowedips_error {
        peer_col = peer_col.push(error_label(msg));
    }

    peer_col = peer_col.push(labelled(
        "Keepalive",
        text_input(
            "25",
            &peer
                .persistent_keepalive
                .map(|k| k.to_string())
                .unwrap_or_default(),
        )
        .on_input(move |v| Message::EditorFieldChanged(EditorField::PeerKeepalive(idx, v)))
        .padding(6)
        .width(Length::Fixed(80.0))
        .into(),
    ));

    container(peer_col.padding(Padding::from([10, 14])))
        .width(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Bottom action bar
// ─────────────────────────────────────────────────────────────────────────────

fn action_bar(is_raw: bool) -> Element<'static, Message> {
    let toggle_label = if is_raw {
        "Structured Editor"
    } else {
        "Raw Editor"
    };

    row![
        button(toggle_label).on_press(Message::EditorToggleRaw),
        iced::widget::Space::new().width(Length::Fill),
        button("Cancel").on_press(Message::EditorCancel),
        button("Save").on_press(Message::EditorSave),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .padding(Padding::from([8, 0]))
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: structured editor
// ─────────────────────────────────────────────────────────────────────────────

/// Render the structured profile editor.
pub fn editor(state: &State) -> Element<'_, Message> {
    let Some(editor) = &state.editor else {
        return text("No profile open").into();
    };

    let mut content = column![].spacing(16).padding(Padding::from([12, 20]));

    // Banner.
    if let Some(banner) = banner_row(state) {
        content = content.push(banner);
    }

    // Interface fields.
    content = content.push(interface_section(editor));

    // Peers divider.
    if !editor.draft.peers.is_empty() {
        content = content.push(
            text("── Peers ──────────────────────────────────")
                .size(13)
                .color(muted_color()),
        );
    }

    // Peer blocks.
    for (idx, peer) in editor.draft.peers.iter().enumerate() {
        content = content.push(peer_section(peer, idx, &editor.validation_errors));
    }

    // Add Peer.
    content = content.push(
        button("+ Add Peer")
            .on_press(Message::EditorFieldChanged(EditorField::AddPeer))
            .padding(Padding::from([6, 14])),
    );

    content = content.push(iced::widget::Space::new().height(Length::Fixed(8.0)));

    // Validation summary.
    if !editor.validation_errors.is_empty() {
        let mut err_col = column![text("Validation errors:").color(error_color()).size(13)]
            .spacing(4)
            .padding(Padding::from([6, 0]));
        for (field, msg) in &editor.validation_errors {
            err_col = err_col.push(
                text(format!("• {field}: {msg}"))
                    .size(12)
                    .color(error_color()),
            );
        }
        content = content.push(err_col);
    }

    // Action bar.
    content = content.push(action_bar(false));

    scrollable(container(content).width(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: raw editor
// ─────────────────────────────────────────────────────────────────────────────

/// Render the raw `.conf` text editor.
///
/// Borrows the persisted [`text_editor::Content`] held on `state`
/// (`state.raw_editor_content`). The reducer mutates that `Content` in place via
/// `perform(action)` on every [`Message::RawEditorAction`], so the cursor and
/// selection survive across frames — that is what makes Backspace/Delete work.
/// The widget's `&'a Content` requirement is satisfied by the ordinary borrow of
/// `state`, so no lifetime tricks are needed.
pub fn raw_editor(state: &State) -> Element<'_, Message> {
    let Some(editor) = &state.editor else {
        return text("No profile open").into();
    };

    let editor_widget: Element<'_, Message> = text_editor(&state.raw_editor_content)
        .on_action(Message::RawEditorAction)
        .height(Length::Fill)
        .into();

    let mut outer = column![].spacing(12).padding(Padding::from([12, 20]));

    // Banner.
    if let Some(b) = state.banner.as_ref() {
        let color = match b.kind {
            BannerKind::Info => muted_color(),
            BannerKind::Success => success_color(),
            BannerKind::Warning => warning_color(),
            BannerKind::Error => error_color(),
        };
        outer = outer.push(
            container(
                row![
                    text(b.message.clone()).color(color).width(Length::Fill),
                    button("✕").on_press(Message::DismissBanner),
                ]
                .spacing(8)
                .padding(Padding::from([6, 12])),
            )
            .width(Length::Fill),
        );
    }

    // Heading.
    outer = outer.push(
        text(format!(
            "Raw editor — {}",
            if editor.profile_name.is_empty() {
                "new profile"
            } else {
                &editor.profile_name
            }
        ))
        .size(16),
    );

    // Parse-error hint.
    if editor
        .validation_errors
        .iter()
        .any(|(f, _)| f.starts_with("Interface") || f.starts_with("Peer"))
    {
        outer = outer.push(
            text("Profile has validation errors — fix them before saving.")
                .size(12)
                .color(warning_color()),
        );
    }

    // Text editor.
    outer = outer.push(editor_widget);

    // Action bar.
    outer = outer.push(action_bar(true));

    container(outer)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
