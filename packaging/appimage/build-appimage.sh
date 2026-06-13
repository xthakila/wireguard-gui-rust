#!/usr/bin/env bash
# build-appimage.sh — Build an AppImage for WireGuard GUI (unofficial).
#
# Usage:
#   ./packaging/appimage/build-appimage.sh [--skip-cargo]
#
#   --skip-cargo   Skip "cargo build --release" (use if you already built the
#                  binary and want a faster packaging-only run).
#
# Prerequisites on the build host:
#   • Rust toolchain (cargo) — unless --skip-cargo is passed
#   • wireguard-tools (wg, wg-quick) — bundled into the AppImage
#   • wget or curl  (downloads linuxdeploy and its GTK plugin)
#   • FUSE or squashfs-tools (linuxdeploy needs one of these at runtime)
#   • GTK 3 development headers (for the rfd file-dialog at runtime)
#
# Approach:
#   1. Optionally build the release binary via cargo.
#   2. Assemble an AppDir following the AppImage convention:
#        AppDir/
#          AppRun                              ← custom launcher (sets PATH/GTK env)
#          wireguard-gui-rust.desktop          ← symlink at root (linuxdeploy req.)
#          wireguard-gui-rust.png              ← symlink at root (linuxdeploy req.)
#          usr/bin/wireguard-gui               ← application binary
#          usr/bin/wg                          ← bundled from host wireguard-tools
#          usr/bin/wg-quick                    ← bundled from host wireguard-tools
#          usr/share/applications/wireguard-gui-rust.desktop
#          usr/share/icons/hicolor/256x256/apps/wireguard-gui-rust.png
#   3. Download linuxdeploy + linuxdeploy-plugin-gtk (GTK 3) if not cached.
#   4. Run linuxdeploy --output appimage, which:
#        • copies shared libraries required by the binary
#        • deploys GTK3 typelibs / pixbuf loaders via the GTK plugin
#        • packages everything into a self-contained .AppImage
#
# NOTE: "WireGuard" is a registered trademark of Jason A. Donenfeld.
#       This is an UNOFFICIAL community build NOT endorsed by WireGuard.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

APP_NAME="wireguard-gui"           # installed binary name
DISPLAY_NAME="WireGuard GUI"       # human-readable (desktop Name=)
DESKTOP_ID="wireguard-gui-rust"    # .desktop basename + icon theme name
POLKIT_ACTION="org.wireguardgui.rust.manage"
GITHUB_REPO="xthakila/wireguard-gui-rust"

# linuxdeploy release tag + asset names (pinned for reproducibility).
LINUXDEPLOY_VERSION="1-alpha-20250213-1"
LINUXDEPLOY_URL="https://github.com/linuxdeploy/linuxdeploy/releases/download/${LINUXDEPLOY_VERSION}/linuxdeploy-x86_64.AppImage"
LINUXDEPLOY_GTK_URL="https://github.com/linuxdeploy/linuxdeploy-plugin-gtk/releases/download/continuous/linuxdeploy-plugin-gtk-x86_64.AppImage"

# GTK version required by the rfd file-dialog (native GTK3 picker).
DEPLOY_GTK_VERSION=3

# ── Derived paths ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/target/appimage-build"
APPDIR="${BUILD_DIR}/AppDir"
TOOLS_DIR="${BUILD_DIR}/tools"
OUTPUT_DIR="${REPO_ROOT}"          # .AppImage lands in the repo root

BINARY_SRC="${REPO_ROOT}/target/release/${APP_NAME}"
ICON_SRC="${REPO_ROOT}/assets/icons/hicolor/256x256/apps/${DESKTOP_ID}.png"

# ── Helpers ───────────────────────────────────────────────────────────────────

info()  { echo "▸ $*"; }
die()   { echo "✖ ERROR: $*" >&2; exit 1; }

download() {
    local url="$1" dest="$2"
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "${dest}" "${url}"
    elif command -v curl &>/dev/null; then
        curl -fsSL -o "${dest}" "${url}"
    else
        die "Neither wget nor curl is available; cannot download ${url}"
    fi
}

# ── Parse arguments ───────────────────────────────────────────────────────────

SKIP_CARGO=0
for arg in "$@"; do
    case "${arg}" in
        --skip-cargo) SKIP_CARGO=1 ;;
        *) die "Unknown argument: ${arg}" ;;
    esac
done

# ── Step 1: Build the release binary ─────────────────────────────────────────

if [[ "${SKIP_CARGO}" -eq 0 ]]; then
    info "Building release binary (cargo build --release)..."
    cd "${REPO_ROOT}"
    cargo build --release
else
    info "--skip-cargo passed; skipping cargo build."
fi

[[ -f "${BINARY_SRC}" ]] || die "Release binary not found at ${BINARY_SRC}. Build first."
[[ -f "${ICON_SRC}" ]]   || die "256x256 icon not found at ${ICON_SRC}."

# ── Step 2: Assemble AppDir ───────────────────────────────────────────────────

info "Assembling AppDir at ${APPDIR}..."

# Clean slate for a reproducible build.
rm -rf "${APPDIR}"

# Standard FHS-inside-AppDir layout.
mkdir -p \
    "${APPDIR}/usr/bin" \
    "${APPDIR}/usr/share/applications" \
    "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

# 2a. Application binary.
info "  Copying binary: ${APP_NAME}"
cp "${BINARY_SRC}" "${APPDIR}/usr/bin/${APP_NAME}"
chmod 755 "${APPDIR}/usr/bin/${APP_NAME}"

# 2b. Bundle wg and wg-quick from the host.
#     wireguard-tools must be installed on the build machine.  The bundled
#     copies let the AppImage work on systems that do not have wireguard-tools
#     installed, though a kernel with WireGuard support is still required.
for tool in wg wg-quick; do
    tool_path="$(command -v "${tool}" 2>/dev/null || true)"
    if [[ -z "${tool_path}" ]]; then
        die "Cannot find '${tool}' on PATH. Install wireguard-tools on the build host."
    fi
    info "  Bundling ${tool} from ${tool_path}"
    cp "${tool_path}" "${APPDIR}/usr/bin/${tool}"
    chmod 755 "${APPDIR}/usr/bin/${tool}"
done

# wg-quick is a shell script; ensure bash is available (it uses #!/bin/bash).
# We rely on the host bash being present at /bin/bash on the target — this is
# true for all mainstream Linux distros.  We do NOT bundle bash itself to avoid
# bloating the image and licensing complexity.

# 2c. .desktop file.
info "  Writing .desktop file"
cat > "${APPDIR}/usr/share/applications/${DESKTOP_ID}.desktop" << EOF
[Desktop Entry]
Name=${DISPLAY_NAME}
Comment=Manage WireGuard VPN tunnels (unofficial; not affiliated with WireGuard)
Exec=${APP_NAME} %u
Icon=${DESKTOP_ID}
Terminal=false
Type=Application
Categories=Network;VPN;
Keywords=wireguard;vpn;tunnel;
MimeType=application/x-wireguard-config;
StartupWMClass=${APP_NAME}
X-Polkit-Action=${POLKIT_ACTION}
EOF

# 2d. 256x256 icon.
info "  Copying icon"
cp "${ICON_SRC}" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/${DESKTOP_ID}.png"

# 2e. Custom AppRun (sets PATH + GTK env, then execs the binary).
info "  Installing AppRun"
cp "${SCRIPT_DIR}/AppRun" "${APPDIR}/AppRun"
chmod 755 "${APPDIR}/AppRun"

# 2f. linuxdeploy requires the .desktop and icon as symlinks at the AppDir root.
info "  Creating root-level symlinks for linuxdeploy"
ln -sf "usr/share/applications/${DESKTOP_ID}.desktop" "${APPDIR}/${DESKTOP_ID}.desktop"
ln -sf "usr/share/icons/hicolor/256x256/apps/${DESKTOP_ID}.png" "${APPDIR}/${DESKTOP_ID}.png"

# ── Step 3: Download linuxdeploy tools (cached in BUILD_DIR/tools) ─────────────

mkdir -p "${TOOLS_DIR}"

LINUXDEPLOY="${TOOLS_DIR}/linuxdeploy-x86_64.AppImage"
LINUXDEPLOY_GTK="${TOOLS_DIR}/linuxdeploy-plugin-gtk-x86_64.AppImage"

if [[ ! -f "${LINUXDEPLOY}" ]]; then
    info "Downloading linuxdeploy..."
    download "${LINUXDEPLOY_URL}" "${LINUXDEPLOY}"
    chmod +x "${LINUXDEPLOY}"
else
    info "linuxdeploy already cached at ${LINUXDEPLOY}"
fi

if [[ ! -f "${LINUXDEPLOY_GTK}" ]]; then
    info "Downloading linuxdeploy-plugin-gtk (GTK ${DEPLOY_GTK_VERSION})..."
    download "${LINUXDEPLOY_GTK_URL}" "${LINUXDEPLOY_GTK}"
    chmod +x "${LINUXDEPLOY_GTK}"
else
    info "linuxdeploy-plugin-gtk already cached at ${LINUXDEPLOY_GTK}"
fi

# ── Step 4: Run linuxdeploy --output appimage ─────────────────────────────────
#
# Key environment variables:
#   DEPLOY_GTK_VERSION=3      tells the GTK plugin which GTK major version to
#                             bundle (matches the rfd file-picker dependency).
#   OUTPUT                    linuxdeploy places the .AppImage here.
#   LDAI_UPDATE_INFORMATION   embed an update URL so AppImageUpdate can work
#                             (optional; set to a GitHub releases zsync URL).
#
# linuxdeploy will:
#   • Run ldd on usr/bin/wireguard-gui and copy all required .so files.
#   • Invoke the GTK plugin, which adds GTK3 typelibs, pixbuf loaders, and
#     theme engines so GTK file-dialogs work on non-GTK desktops (e.g. KDE).
#   • Pack everything with appimagetool into a type-2 AppImage.
#
# We pass --custom-apprun to preserve our AppRun (linuxdeploy would otherwise
# overwrite it with its own generic one that does not set our PATH / GTK env).

info "Running linuxdeploy to assemble the AppImage..."

DEPLOY_GTK_VERSION=${DEPLOY_GTK_VERSION} \
OUTPUT="${OUTPUT_DIR}" \
    "${LINUXDEPLOY}" \
        --appdir "${APPDIR}" \
        --desktop-file "${APPDIR}/usr/share/applications/${DESKTOP_ID}.desktop" \
        --icon-file "${APPDIR}/usr/share/icons/hicolor/256x256/apps/${DESKTOP_ID}.png" \
        --plugin gtk \
        --custom-apprun "${APPDIR}/AppRun" \
        --output appimage

# ── Done ──────────────────────────────────────────────────────────────────────

APPIMAGE_FILE="$(find "${OUTPUT_DIR}" -maxdepth 1 -name "${DISPLAY_NAME// /_}*.AppImage" -newer "${APPDIR}/AppRun" | head -1 || true)"
if [[ -z "${APPIMAGE_FILE}" ]]; then
    # linuxdeploy may use different spacing; try a broader glob.
    APPIMAGE_FILE="$(find "${OUTPUT_DIR}" -maxdepth 1 -name "*.AppImage" -newer "${APPDIR}/AppRun" | head -1 || true)"
fi

echo ""
info "Build complete."
if [[ -n "${APPIMAGE_FILE}" ]]; then
    info "AppImage: ${APPIMAGE_FILE}"
    info "Size:     $(du -sh "${APPIMAGE_FILE}" | cut -f1)"
fi
echo ""
echo "  IMPORTANT — Runtime prerequisites on the end-user system:"
echo "    • Linux kernel with WireGuard support (≥ 5.6, or backport ≥ 4.19)"
echo "    • FUSE 2 or FUSE 3 to mount the AppImage"
echo "    • Root / polkit for 'ip' and tunnel operations (polkit action: ${POLKIT_ACTION})"
echo "    • NetworkManager (preferred) or iproute2 for network management"
echo ""
echo "  wg and wg-quick are bundled; no system wireguard-tools install required."
echo ""
echo "  NOTE: WireGuard is a trademark of Jason A. Donenfeld."
echo "        This AppImage is unofficial and is not affiliated with or"
echo "        endorsed by the WireGuard project."
