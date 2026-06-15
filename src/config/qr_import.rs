//! QR-code profile import (feature 4).
//!
//! Many WireGuard providers hand out a tunnel as a QR code that encodes the full
//! `.conf` text. [`decode_qr_image`] loads an image file, decodes the QR with the
//! pure-Rust [`rqrr`] decoder, and returns the embedded text — which the caller
//! then feeds to [`crate::config::profile::WgProfile::from_conf_str`] to build a
//! profile exactly as the file-import path does.
//!
//! Pure decode only: no privileged code, no network. The reducer owns the file
//! picker (rfd) and the parse step.

use std::path::Path;

use crate::error::{AppError, AppResult};

/// Decode the QR code in the image at `path` and return its embedded text.
///
/// Loads the image (via the `image` crate, already a dependency), greyscales it,
/// and runs [`rqrr`] over it. Returns the decoded payload — for a WireGuard QR
/// this is the `.conf` text. Errors map to [`AppError::ImportFailed`] so the UI
/// surfaces a single consistent import-failure banner:
///   - the image can't be read/decoded,
///   - no QR grid is found in the image,
///   - the QR fails to decode (damaged / unsupported).
pub fn decode_qr_image(path: &Path) -> AppResult<String> {
    // Detect the format from the file *content* (magic bytes), not the extension:
    // a QR image the user picks from the file dialog may have no extension or a
    // wrong one (and `image::open` keys purely on the extension). `ImageReader`'s
    // `with_guessed_format` sniffs the leading bytes so PNG/JPEG/etc. decode
    // regardless of the file name.
    let img = image::ImageReader::open(path)
        .map_err(|e| AppError::ImportFailed(format!("read image {path:?}: {e}")))?
        .with_guessed_format()
        .map_err(|e| AppError::ImportFailed(format!("read image {path:?}: {e}")))?
        .decode()
        .map_err(|e| AppError::ImportFailed(format!("decode image {path:?}: {e}")))?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    let grid = grids
        .first()
        .ok_or_else(|| AppError::ImportFailed("no QR code found in image".to_owned()))?;

    let (_meta, content) = grid
        .decode()
        .map_err(|e| AppError::ImportFailed(format!("QR decode failed: {e}")))?;

    Ok(content)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure only (no root, no network, no display, no privileged ops).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic (but synthetic) WireGuard client `.conf` used as the round-trip
    /// payload. It must fit inside a single QR code (the `qrcode` crate handles
    /// capacity automatically; a typical WireGuard conf is well within Version-40 at
    /// ~2900 bytes of byte-mode data).
    const SAMPLE_CONF: &str = "\
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.7.0.2/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
";

    /// Encode `SAMPLE_CONF` as a QR PNG (via [`crate::server::qr_png`]), write the
    /// bytes to a temporary file, then decode with [`decode_qr_image`] and assert
    /// the round-trip produces byte-identical output.
    ///
    /// This is a REAL encode→decode proof: the QR image is rendered in memory,
    /// serialised to a real temp file on disk, and then fully decoded through the
    /// rqrr detector/decoder pipeline — no mocking, no network, no root.
    #[test]
    fn decode_qr_image_round_trips_wireguard_conf() {
        // Step 1 — encode the conf to a QR PNG using the crate's own encoder.
        let png_bytes = crate::server::qr_png(SAMPLE_CONF)
            .expect("qr_png should succeed for a typical WireGuard conf");

        // Step 2 — write the PNG to a named temporary file so decode_qr_image can
        //           open it via a filesystem path (matching production usage).
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), &png_bytes)
            .expect("failed to write QR PNG to temp file");

        // Step 3 — decode via the public API under test.
        let decoded = decode_qr_image(tmp.path())
            .expect("decode_qr_image should successfully decode the generated QR");

        // Step 4 — assert byte-exact round-trip.
        assert_eq!(
            decoded, SAMPLE_CONF,
            "decoded text must exactly match the original conf (round-trip failed)"
        );
    }

    /// Verify that a non-image file (e.g. a text file) is rejected with
    /// [`AppError::ImportFailed`] and not a panic.
    #[test]
    fn decode_qr_image_rejects_non_image_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), b"this is not an image").expect("write");

        let err = decode_qr_image(tmp.path())
            .expect_err("expected ImportFailed for a non-image file");
        assert!(
            matches!(err, AppError::ImportFailed(_)),
            "error must be ImportFailed, got: {err:?}"
        );
    }

    /// Verify that a valid PNG that contains NO QR code is rejected with
    /// [`AppError::ImportFailed`] ("no QR code found in image"), not a panic.
    #[test]
    fn decode_qr_image_rejects_png_without_qr() {
        // Build a 16×16 all-white PNG (no QR pattern).
        use image::{GrayImage, Luma};
        let img: GrayImage = GrayImage::from_pixel(16, 16, Luma([255u8]));
        let mut png_bytes: Vec<u8> = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )
        .expect("encode blank PNG");

        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), &png_bytes).expect("write");

        let err = decode_qr_image(tmp.path())
            .expect_err("expected ImportFailed for a PNG with no QR code");
        assert!(
            matches!(err, AppError::ImportFailed(_)),
            "error must be ImportFailed, got: {err:?}"
        );
    }
}
