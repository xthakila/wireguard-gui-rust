<div align="center">
  <img src="assets/icons/hicolor/256x256/apps/wireguard-gui-rust.png" width="128" alt="WireGuard GUI (Rust)"/>
  <h1>WireGuard GUI (Rust)</h1>
  <p><strong>A fast, lightweight, 100% pure-Rust WireGuard VPN manager for Linux.</strong></p>
</div>

A from-scratch [Rust](https://www.rust-lang.org/) rewrite of
[`0xle0ne/wireguard-gui`](https://github.com/0xle0ne/wireguard-gui) — it replaces the original's
Tauri + Next.js WebView stack with a native [Iced](https://iced.rs/) UI. No WebView, no JavaScript
runtime, no `libappindicator` C dependency: a single small native binary.

> *WireGuard is a registered trademark of Jason A. Donenfeld. This is an independent, unofficial
> project and is not affiliated with or endorsed by Jason A. Donenfeld or the WireGuard project.
> It does not use the official WireGuard logo.*

## Status

**v0.2.0 — client + server, 428 tests.** The client connect bug is fixed and **proven** (a real
tunnel interface comes up via NetworkManager/`wg-quick`); the raw editor, tray, structured editor,
Plan preview, and packaging all work. **Server mode** is implemented and proven to bring up a real
`wg` interface with registered peers. Still wants hands-on testing on *your* machine with a real
peer: a live end-to-end handshake, the kill-switch against live traffic, on-host NAT/forwarding, and
connect-on-boot across a reboot (all require root + a real WireGuard endpoint).

## Features

- **Profiles** — list / create / edit / delete / import / export `.conf`
- **Structured, validated editor** — Interface + Peers fields with live validation, plus a raw-text
  view and one-click **x25519 keypair generation** (pure Rust)
- **Plan mode** — a no-root **dry-run preview** of exactly what a profile will do (addresses, routed
  `AllowedIPs`, DNS, endpoint, full- vs split-tunnel) *before* you connect
- **Connect / disconnect** one tunnel at a time, via **NetworkManager** (`nmcli`) or **`wg-quick`**
- **System tray** with live connected/disconnected status; **close-to-tray**; guaranteed single instance
- **Auto-reconnect** (handshake-watchdog with back-off), **start-on-login**, **connect-on-boot**
- **Kill-switch** with a lockout-prevention allow-list and a dead-man lease (auto-restores your
  network if the app dies)
- **Split tunnelling** — by destination (`AllowedIPs`) *and* per-application (network namespaces),
  as two independent, non-interfering subsystems
- **Server mode** — run this machine as a WireGuard server: create a server, add/remove client peers
  (each gets a ready `.conf` + a **QR code** for mobile), an internet-gateway toggle (NAT +
  forwarding), and start/stop with live per-peer status — coexists with the client
- **Follow system light/dark** theme

## Install

Installing the GUI **also pulls in WireGuard** (`wireguard-tools`) automatically — one step.

### Debian / Ubuntu (`.deb`)
```sh
sudo apt install ./wireguard-gui_0.2.1-1_amd64.deb   # resolves wireguard-tools for you
```

### AppImage (portable)
```sh
chmod +x WireGuard_GUI-x86_64.AppImage
./WireGuard_GUI-x86_64.AppImage
```
The AppImage bundles `wg`/`wg-quick`. (The kill-switch / per-app / `wg-quick`-fallback paths use a
polkit helper that a system package installs; from an AppImage the **NetworkManager** path works
out of the box.)

### Arch (AUR)
```sh
yay -S wireguard-gui-rust        # build from source
# or: yay -S wireguard-gui-rust-bin   # prebuilt
```

### Snap
```sh
sudo snap install wireguard-gui
sudo snap connect wireguard-gui:network-manager
sudo snap connect wireguard-gui:network-control
```

## Build from source

```sh
cargo build --release
```
Needs a recent stable Rust toolchain and the usual desktop build libs (`libxkbcommon`,
`wayland`/`x11`, `fontconfig`, `libdbus-1`). `wireguard-tools` is required at runtime.

## Architecture

| Crate part | Role |
|---|---|
| `src/app.rs` | The Iced application: a single `State` + `Message` reducer (Elm-style) |
| `src/ui/*` | Per-screen views (status, profile list, editor, plan, settings) |
| `src/config/*` | `.conf` parser/validator, profile store, pure-Rust x25519 keygen |
| `src/wg/*` | `wg show` status parsing, dry-run Plan, `nmcli` + `wg-quick` backends |
| `src/net/*` | kill-switch (nftables), per-app netns, auto-reconnect watchdog, connect-on-boot |
| `src/bin/helper.rs` | the **only** code that runs as root, behind a single polkit action |
| `src/tray.rs` · `src/single_instance.rs` | ksni tray · abstract-socket single-instance + window-raise IPC |

**Privilege model:** the GUI never runs as root. Privileged operations are serialized into a
`PrivCmd` and handed to a small helper that runs via `pkexec` under one polkit action
(`org.wireguardgui.rust.manage`). The GUI and helper share the *exact* same `PrivCmd` definition so
they can never drift.

`wg-quick` is AppArmor-confined to `/etc/wireguard`, so the `wg-quick` fallback path routes the
client conf through the helper exactly like the server does: `ClientWriteConf` writes the generated
text to `/etc/wireguard/wg-gui0.conf` (0600, in-band so the private key never lands in a
world-readable temp file), then the GUI runs `wg-quick up wg-gui0` *by interface name* (not a
`/run`/`/tmp` path that AppArmor would reject); disconnect runs `wg-quick down wg-gui0` and
`ClientRemoveConf`. The **NetworkManager** path is unaffected (NM reads the conf itself, unconfined).

**End-to-end proof:** `src/server/e2e.rs::server_client_handshake_e2e` (gated `#[ignore]`, needs
root) stands up a real tunnel between two network namespaces from the *app-generated* server/client
configs and asserts a ping plus a recent handshake and non-zero transfer on both sides. Run it with
`cargo test --bin wireguard-gui server::e2e -- --ignored --nocapture` as root.

## Tray on GNOME

GNOME does not show `StatusNotifierItem` tray icons out of the box. On Ubuntu the
**AppIndicator/KStatusNotifierItem Support** extension ships and is enabled by default; on other
GNOME setups, install that extension for the tray icon to appear. KDE and most other desktops work
without anything extra.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Credits

Inspired by and a rewrite of [`0xle0ne/wireguard-gui`](https://github.com/0xle0ne/wireguard-gui).
