<div align="center">
  <h1>WireGuard GUI (Rust)</h1>
  <p><strong>A fast, lightweight, 100% pure-Rust WireGuard VPN manager for Linux.</strong></p>
</div>

> ⚠️ **Status: under active development (Phase 3 — privileged backend + app wiring).** Not yet
> released. The pure-Rust backend (Phase 1: profiles, keygen, store, tunnel backends, status,
> plan, settings, single-instance, autostart, public-IP) is done and tested. The real Iced
> application is wired up (`src/app.rs` owns the frozen `State`/`Message` + reducer; `src/main.rs`
> drives the tray + single-instance + windowed/daemon launch).
>
> **Phase 3 (now integrated):** the root-only helper (`src/bin/helper.rs`, the single privileged
> binary, launched via `pkexec` + one polkit action) implements the wg-quick fallback, the
> nftables kill-switch (lockout-prevention allow-list + `systemd-run` dead-man lease),
> per-app network namespaces, and the systemd connect-on-boot unit. The GUI never runs
> privileged code — it builds a frozen `PrivCmd` (`src/net/privilege.rs`) and hands it to the
> helper. `src/app.rs` now wires: **kill-switch** (arm on a successful connect when enabled,
> disarm on disconnect; toggle in Settings), **auto-reconnect** (`src/net/watchdog.rs` pure
> decision + exponential back-off, evaluated each status tick, suppressed on user disconnect),
> and **connect-on-boot** (`src/net/boot.rs`: NetworkManager autoconnect on the non-root path,
> or `BootEnableSystemd` via the helper for the wg-quick path). Kill-switch and connect-on-boot
> are **OFF by default**. The per-screen views in `src/ui/*` are still being filled in. This
> README will gain screenshots and install docs as the build progresses.

A from-scratch [Rust](https://www.rust-lang.org/) rewrite of
[`0xle0ne/wireguard-gui`](https://github.com/0xle0ne/wireguard-gui) — replacing the Tauri + Next.js
WebView stack with a native, pure-Rust [Iced](https://iced.rs/) UI for a much smaller, faster app.

> *WireGuard is a registered trademark of Jason A. Donenfeld. This is an independent, unofficial
> project and is not affiliated with or endorsed by the WireGuard project.*

## Why a rewrite?

The original is a capable profile manager, but ships a full system WebView + Node/JS frontend. This
rewrite keeps the good ideas and makes the app:

- **Light & fast** — no WebView, no JS runtime, no GTK toolkit lock-in; a single native binary.
- **Pure Rust** — UI ([Iced](https://iced.rs/)), tray ([ksni](https://crates.io/crates/ksni), no
  `libappindicator` C dependency), config parsing, and x25519 keygen are all Rust.
- **Better UX** — a structured, validated config editor plus a no-root **dry-run "Plan"** preview.
- **Fixed bugs** — a reliable system tray and guaranteed single-instance.

## Planned features

- Profile management: list / create / edit / delete / import / export `.conf`
- Connect / disconnect (one active tunnel), via NetworkManager (`nmcli`) or `wg-quick`
- Structured + validated config editor with keypair generation; raw-text view
- **Plan mode**: dry-run preview of exactly what a profile will route before connecting
- System tray with live connected/disconnected status; close-to-tray
- Auto-reconnect, start-on-login, connect-on-boot
- Kill-switch (with lockout-prevention) and split tunnelling (by destination *and* per-app)
- Follow system light/dark theme
- One-step install that also pulls in WireGuard (deb / AppImage / snap / AUR)

## Building from source

```sh
cargo build --release
```

Requires a recent stable Rust toolchain and standard desktop build libraries
(`libxkbcommon`, `wayland`/`x11`, `fontconfig`). WireGuard itself
(`wireguard-tools`) is required at runtime.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
