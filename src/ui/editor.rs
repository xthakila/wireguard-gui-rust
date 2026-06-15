//! Profile editor + raw-text editor screens.
//!
//! `editor` renders the structured form (Interface fields + Peers).
//! `raw_editor` renders a full-height text editor for the raw `.conf` content.
//!
//! All colours, spacing, card surfaces, buttons, and icons come from
//! [`crate::ui::theme`] so this screen stays cohesive with the rest of the app.
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
use iced::{Background, Border, Color, Element, Length, Padding, Shadow, Theme, Vector};

use crate::app::{BannerKind, EditorField, EditorState, Message, State};
use crate::ui::theme::{
    self, body, card_style, ghost, icon, icons, primary, section_title,
    CARD_PADDING, RADIUS_CONTROL, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL, SPACE_XS,
    TEXT_BODY, TEXT_CAPTION,
};

// ─────────────────────────────────────────────────────────────────────────────
// Inline text-input styling
//
// iced 0.14 `text_input` takes a `.style(closure)` that receives `(theme, status)`.
// We build a custom closure here that derives colours from our palette so inputs
// look like first-class citizens of the design (background=surface_alt, accent
// border on focus, danger border when the field has an error).
// ─────────────────────────────────────────────────────────────────────────────

fn input_style(
    has_error: bool,
) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
    move |theme: &Theme, status: text_input::Status| {
        let p = theme::palette(theme);
        let border_color = if has_error {
            p.danger
        } else {
            match status {
                text_input::Status::Focused { .. } => p.accent,
                _ => p.border,
            }
        };
        text_input::Style {
            background: Background::Color(p.surface_alt),
            border: Border {
                color: border_color,
                width: 1.0,
                radius: RADIUS_CONTROL.into(),
            },
            icon: p.muted,
            placeholder: Color { a: 0.5, ..p.muted },
            value: p.text,
            selection: Color { a: 0.3, ..p.accent },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner (uses theme palette)
// ─────────────────────────────────────────────────────────────────────────────

fn banner_row(state: &State) -> Option<Element<'_, Message>> {
    let b = state.banner.as_ref()?;

    let banner = container(
        row![
            text(b.message.clone())
                .size(TEXT_BODY)
                .style(move |theme: &Theme| {
                    let p = theme::palette(theme);
                    text::Style {
                        color: Some(match b.kind {
                            BannerKind::Info => p.muted,
                            BannerKind::Success => p.success,
                            BannerKind::Warning => p.warning,
                            BannerKind::Error => p.danger,
                        }),
                    }
                })
                .width(Length::Fill),
            button(icon(icons::STOP))
                .on_press(Message::DismissBanner)
                .style(ghost())
                .padding([SPACE_XS, SPACE_SM]),
        ]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center)
        .padding(Padding::from([SPACE_SM, SPACE_MD])),
    )
    .width(Length::Fill)
    .style(move |theme: &Theme| {
        let p = theme::palette(theme);
        let accent_c = match b.kind {
            BannerKind::Info => p.muted,
            BannerKind::Success => p.success,
            BannerKind::Warning => p.warning,
            BannerKind::Error => p.danger,
        };
        container::Style {
            text_color: Some(p.text),
            background: Some(Background::Color(Color { a: 0.10, ..accent_c })),
            border: Border {
                color: Color { a: 0.35, ..accent_c },
                width: 1.0,
                radius: RADIUS_CONTROL.into(),
            },
            shadow: Shadow::default(),
            snap: false,
        }
    });

    Some(banner.into())
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
        .size(TEXT_CAPTION)
        .style(|theme: &Theme| text::Style {
            color: Some(theme::palette(theme).danger),
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Labelled field helper
// ─────────────────────────────────────────────────────────────────────────────

/// A row with a fixed-width label on the left and a widget on the right.
/// The label is muted at caption size; the widget expands to fill available space.
fn labelled<'a>(label_text: &'a str, widget: Element<'a, Message>) -> Element<'a, Message> {
    row![
        text(label_text)
            .size(TEXT_CAPTION)
            .style(|theme: &Theme| text::Style {
                color: Some(theme::palette(theme).muted),
            })
            .width(Length::Fixed(130.0)),
        widget,
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center)
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface section card
// ─────────────────────────────────────────────────────────────────────────────

fn interface_section<'a>(editor: &'a EditorState) -> Element<'a, Message> {
    let draft = &editor.draft;
    let errors = &editor.validation_errors;

    let privkey_error = first_error_for(errors, "Interface.PrivateKey");
    let address_error = first_error_for(errors, "Interface.Address");

    // Profile name field — disabled when editing an existing profile.
    let name_input: Element<'_, Message> = if editor.is_new {
        text_input("e.g. home-vpn", &editor.profile_name)
            .on_input(|v| Message::EditorFieldChanged(EditorField::ProfileName(v)))
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(false))
            .width(Length::Fill)
            .into()
    } else {
        // Existing profile: name is read-only (no on_input binding).
        text_input("", &editor.profile_name)
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(false))
            .width(Length::Fill)
            .into()
    };

    // PrivateKey row: input + generate button.
    let privkey_row: Element<'_, Message> = row![
        text_input("Base-64 private key", &draft.interface.private_key)
            .on_input(|v| Message::EditorFieldChanged(EditorField::PrivateKey(v)))
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(privkey_error.is_some()))
            .width(Length::Fill),
        button(
            row![
                icon(icons::REFRESH),
                text(" Generate").size(TEXT_BODY),
            ]
            .spacing(SPACE_XS)
            .align_y(iced::Alignment::Center),
        )
        .on_press(Message::GenerateKeypair)
        .style(ghost())
        .padding([SPACE_SM, SPACE_MD]),
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center)
    .into();

    let mut col = column![
        section_title(format!("{} Interface", icons::LOCK)),
        labelled("Profile Name", name_input),
        labelled("Private Key", privkey_row),
    ]
    .spacing(SPACE_SM);

    if let Some(msg) = privkey_error {
        col = col.push(error_label(msg));
    }

    col = col.push(labelled(
        "Address",
        text_input(
            "10.0.0.2/24, fd00::2/128",
            &draft.interface.address.join(", "),
        )
        .on_input(|v| Message::EditorFieldChanged(EditorField::Address(v)))
        .padding([SPACE_SM, SPACE_MD])
        .style(input_style(address_error.is_some()))
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = address_error {
        col = col.push(error_label(msg));
    }

    col = col
        .push(labelled(
            "DNS",
            text_input("1.1.1.1, 8.8.8.8", &draft.interface.dns.join(", "))
                .on_input(|v| Message::EditorFieldChanged(EditorField::Dns(v)))
                .padding([SPACE_SM, SPACE_MD])
                .style(input_style(false))
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
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(false))
            .width(Length::Fixed(120.0))
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
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(false))
            .width(Length::Fixed(120.0))
            .into(),
        ));

    container(col.padding(CARD_PADDING))
        .width(Length::Fill)
        .style(card_style)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer section card
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

    // Heading row: section title + remove button.
    let heading_row: Element<'_, Message> = row![
        section_title(format!("{} Peer {}", icons::SERVER, idx + 1)).width(Length::Fill),
        button(
            row![
                icon(icons::TRASH),
                text(" Remove").size(TEXT_BODY),
            ]
            .spacing(SPACE_XS)
            .align_y(iced::Alignment::Center),
        )
        .on_press(Message::EditorFieldChanged(EditorField::RemovePeer(idx)))
        .style(theme::danger())
        .padding([SPACE_XS, SPACE_MD]),
    ]
    .spacing(SPACE_SM)
    .align_y(iced::Alignment::Center)
    .into();

    let mut col = column![heading_row]
        .spacing(SPACE_SM)
        .push(labelled(
            "Public Key",
            text_input("Base-64 public key", &peer.public_key)
                .on_input(move |v| {
                    Message::EditorFieldChanged(EditorField::PeerPublicKey(idx, v))
                })
                .padding([SPACE_SM, SPACE_MD])
                .style(input_style(pubkey_error.is_some()))
                .width(Length::Fill)
                .into(),
        ));

    if let Some(msg) = pubkey_error {
        col = col.push(error_label(msg));
    }

    col = col.push(labelled(
        "Preshared Key",
        text_input(
            "Optional — base-64 key",
            peer.preshared_key.as_deref().unwrap_or(""),
        )
        .on_input(move |v| {
            Message::EditorFieldChanged(EditorField::PeerPresharedKey(idx, v))
        })
        .padding([SPACE_SM, SPACE_MD])
        .style(input_style(psk_error.is_some()))
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = psk_error {
        col = col.push(error_label(msg));
    }

    col = col.push(labelled(
        "Endpoint",
        text_input(
            "vpn.example.com:51820",
            peer.endpoint.as_deref().unwrap_or(""),
        )
        .on_input(move |v| {
            Message::EditorFieldChanged(EditorField::PeerEndpoint(idx, v))
        })
        .padding([SPACE_SM, SPACE_MD])
        .style(input_style(endpoint_error.is_some()))
        .width(Length::Fill)
        .into(),
    ));

    if let Some(msg) = endpoint_error {
        col = col.push(error_label(msg));
    }

    col = col.push(labelled(
        "Allowed IPs",
        text_input("0.0.0.0/0, ::/0", &peer.allowed_ips.join(", "))
            .on_input(move |v| {
                Message::EditorFieldChanged(EditorField::PeerAllowedIps(idx, v))
            })
            .padding([SPACE_SM, SPACE_MD])
            .style(input_style(allowedips_error.is_some()))
            .width(Length::Fill)
            .into(),
    ));

    if let Some(msg) = allowedips_error {
        col = col.push(error_label(msg));
    }

    col = col.push(labelled(
        "Keepalive",
        text_input(
            "25",
            &peer
                .persistent_keepalive
                .map(|k| k.to_string())
                .unwrap_or_default(),
        )
        .on_input(move |v| {
            Message::EditorFieldChanged(EditorField::PeerKeepalive(idx, v))
        })
        .padding([SPACE_SM, SPACE_MD])
        .style(input_style(false))
        .width(Length::Fixed(120.0))
        .into(),
    ));

    container(col.padding(CARD_PADDING))
        .width(Length::Fill)
        .style(card_style)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation error summary card
// ─────────────────────────────────────────────────────────────────────────────

fn validation_summary<'a>(errors: &'a [(String, String)]) -> Element<'a, Message> {
    let mut col = column![
        row![
            icon("⚠"),
            text("  Validation errors — fix these before saving.")
                .size(TEXT_BODY)
                .style(|theme: &Theme| text::Style {
                    color: Some(theme::palette(theme).danger),
                }),
        ]
        .align_y(iced::Alignment::Center),
    ]
    .spacing(SPACE_XS);

    for (field, msg) in errors {
        col = col.push(
            text(format!("• {field}: {msg}"))
                .size(TEXT_CAPTION)
                .style(|theme: &Theme| text::Style {
                    color: Some(theme::palette(theme).danger),
                }),
        );
    }

    container(col.padding(CARD_PADDING))
        .width(Length::Fill)
        .style(|theme: &Theme| {
            let p = theme::palette(theme);
            container::Style {
                text_color: Some(p.danger),
                background: Some(Background::Color(Color { a: 0.08, ..p.danger })),
                border: Border {
                    color: Color { a: 0.30, ..p.danger },
                    width: 1.0,
                    radius: RADIUS_CONTROL.into(),
                },
                shadow: Shadow::default(),
                snap: false,
            }
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Bottom action bar
// ─────────────────────────────────────────────────────────────────────────────

fn action_bar(is_raw: bool) -> Element<'static, Message> {
    // Toggle label and icon flips based on the current editor mode.
    let (toggle_icon, toggle_label): (&'static str, &'static str) = if is_raw {
        (icons::EDIT, " Structured")
    } else {
        (icons::EDIT, " Raw")
    };

    container(
        row![
            // Toggle mode (ghost style — secondary action).
            button(
                row![
                    icon(toggle_icon),
                    text(toggle_label).size(TEXT_BODY),
                ]
                .spacing(SPACE_XS)
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::EditorToggleRaw)
            .style(ghost())
            .padding([SPACE_SM, SPACE_MD]),
            // Spacer pushes Save + Cancel to the right.
            iced::widget::Space::new().width(Length::Fill),
            // Cancel (ghost — not destructive, just navigation).
            button(
                row![
                    icon(icons::BACK),
                    text(" Cancel").size(TEXT_BODY),
                ]
                .spacing(SPACE_XS)
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::EditorCancel)
            .style(ghost())
            .padding([SPACE_SM, SPACE_MD]),
            // Save (primary — the main action).
            button(
                row![
                    icon(icons::SHIELD),
                    text(" Save").size(TEXT_BODY),
                ]
                .spacing(SPACE_XS)
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::EditorSave)
            .style(primary())
            .padding([SPACE_SM, SPACE_LG]),
        ]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center),
    )
    .width(Length::Fill)
    .style(|theme: &Theme| {
        let p = theme::palette(theme);
        container::Style {
            text_color: Some(p.text),
            background: Some(Background::Color(p.surface)),
            border: Border {
                color: p.border,
                width: 1.0,
                radius: 0.0.into(),
            },
            shadow: Shadow {
                color: Color { a: 0.18, ..Color::BLACK },
                offset: Vector::new(0.0, -2.0),
                blur_radius: 8.0,
            },
            snap: false,
        }
    })
    .padding(Padding::from([SPACE_SM, SPACE_MD]))
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public: structured editor
// ─────────────────────────────────────────────────────────────────────────────

/// Render the structured profile editor.
pub fn editor(state: &State) -> Element<'_, Message> {
    let Some(editor) = &state.editor else {
        return body("No profile open").into();
    };

    let mut content = column![].spacing(SPACE_MD).padding(Padding::from([SPACE_MD, SPACE_XL]));

    // Banner.
    if let Some(banner) = banner_row(state) {
        content = content.push(banner);
    }

    // Screen title: "Edit Profile" or "New Profile".
    let screen_heading = if editor.is_new {
        format!("{} New Profile", icons::PLUS)
    } else {
        format!("{} Edit Profile", icons::EDIT)
    };
    content = content.push(
        text(screen_heading)
            .size(theme::TEXT_TITLE)
            .style(|theme: &Theme| text::Style {
                color: Some(theme::palette(theme).text),
            }),
    );

    // Interface card.
    content = content.push(interface_section(editor));

    // Peer cards.
    for (idx, peer) in editor.draft.peers.iter().enumerate() {
        content = content.push(peer_section(peer, idx, &editor.validation_errors));
    }

    // Add Peer button — ghost style, full-width look.
    content = content.push(
        container(
            button(
                row![
                    icon(icons::PLUS),
                    text("  Add Peer").size(TEXT_BODY),
                ]
                .spacing(SPACE_XS)
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::EditorFieldChanged(EditorField::AddPeer))
            .style(ghost())
            .padding([SPACE_SM, SPACE_MD]),
        )
        .width(Length::Fill),
    );

    // Validation summary card (only when there are errors).
    if !editor.validation_errors.is_empty() {
        content = content.push(validation_summary(&editor.validation_errors));
    }

    // Bottom spacer so the last card isn't flush against the action bar.
    content = content.push(iced::widget::Space::new().height(Length::Fixed(SPACE_SM)));

    // We wrap in a column that pushes the scrollable content above a pinned action bar.
    column![
        scrollable(
            container(content).width(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill),
        action_bar(false),
    ]
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
        return body("No profile open").into();
    };

    // Profile label for the heading.
    let profile_label = if editor.profile_name.is_empty() {
        "new profile"
    } else {
        &editor.profile_name
    };

    // Has any validation error?
    let has_errors = editor
        .validation_errors
        .iter()
        .any(|(f, _)| f.starts_with("Interface") || f.starts_with("Peer"));

    // The text editor widget — wiring is UNCHANGED; only the container is restyled.
    let editor_widget: Element<'_, Message> = text_editor(&state.raw_editor_content)
        .on_action(Message::RawEditorAction)
        .style(|theme: &Theme, status: text_editor::Status| {
            let p = theme::palette(theme);
            let border_color = match status {
                text_editor::Status::Focused { .. } => p.accent,
                _ => p.border,
            };
            text_editor::Style {
                background: Background::Color(p.surface_alt),
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: RADIUS_CONTROL.into(),
                },
                placeholder: Color { a: 0.5, ..p.muted },
                value: p.text,
                selection: Color { a: 0.25, ..p.accent },
            }
        })
        .height(Length::Fill)
        .into();

    let mut outer = column![].spacing(SPACE_MD).padding(Padding::from([SPACE_MD, SPACE_XL]));

    // Banner.
    if let Some(b) = banner_row(state) {
        outer = outer.push(b);
    }

    // Screen title.
    outer = outer.push(
        text(format!("{} Raw Editor — {}", icons::EDIT, profile_label))
            .size(theme::TEXT_TITLE)
            .style(|theme: &Theme| text::Style {
                color: Some(theme::palette(theme).text),
            }),
    );

    // Parse-error hint — styled as an inline warning pill row.
    if has_errors {
        outer = outer.push(
            container(
                row![
                    icon("⚠"),
                    text("  Profile has validation errors — fix before saving.")
                        .size(TEXT_CAPTION)
                        .style(|theme: &Theme| text::Style {
                            color: Some(theme::palette(theme).warning),
                        }),
                ]
                .align_y(iced::Alignment::Center)
                .spacing(SPACE_XS)
                .padding([SPACE_XS, SPACE_SM]),
            )
            .style(|theme: &Theme| {
                let p = theme::palette(theme);
                container::Style {
                    text_color: Some(p.warning),
                    background: Some(Background::Color(Color { a: 0.10, ..p.warning })),
                    border: Border {
                        color: Color { a: 0.35, ..p.warning },
                        width: 1.0,
                        radius: RADIUS_CONTROL.into(),
                    },
                    shadow: Shadow::default(),
                    snap: false,
                }
            }),
        );
    }

    // Text editor (grows to fill height).
    outer = outer.push(editor_widget);

    column![
        container(outer).width(Length::Fill).height(Length::Fill),
        action_bar(true),
    ]
    .into()
}
