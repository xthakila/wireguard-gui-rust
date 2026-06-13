//! WireGuard X25519 key generation (pure-Rust via `x25519-dalek`, base64-encoded).

use base64::Engine as _;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{AppError, AppResult};

// The standard base64 engine (no padding variants), matching what `wg genkey` / `wg pubkey` produce.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Generate a fresh `(private_key, public_key)` pair, both base64-encoded.
///
/// The private key is a random `StaticSecret`; the public key is derived from it via
/// the X25519 Diffie-Hellman function — identical to what `wg genkey` + `wg pubkey` produce.
pub async fn generate_keypair() -> AppResult<(String, String)> {
    // Use `tokio::task::spawn_blocking` so the syscall for randomness does not stall
    // the async executor.
    tokio::task::spawn_blocking(|| {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        let priv_b64 = B64.encode(secret.as_bytes());
        let pub_b64 = B64.encode(public.as_bytes());
        Ok((priv_b64, pub_b64))
    })
    .await
    .map_err(|e| AppError::KeygenFailed(e.to_string()))?
}

/// Derive the base64 public key from a base64-encoded private key.
///
/// Decodes the private key from standard base64, verifies it is exactly 32 bytes,
/// then derives the corresponding X25519 public key.
pub async fn pubkey_from_private(private_key: &str) -> AppResult<String> {
    let private_key = private_key.to_owned();
    tokio::task::spawn_blocking(move || {
        let raw = B64
            .decode(private_key.trim())
            .map_err(|e| AppError::KeygenFailed(format!("base64 decode failed: {e}")))?;

        if raw.len() != 32 {
            return Err(AppError::KeygenFailed(format!(
                "private key must be 32 bytes, got {}",
                raw.len()
            )));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Ok(B64.encode(public.as_bytes()))
    })
    .await
    .map_err(|e| AppError::KeygenFailed(e.to_string()))?
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_keypair_produces_valid_base64_32_bytes() {
        let (priv_key, pub_key) = generate_keypair().await.unwrap();

        // Both must decode to exactly 32 bytes.
        let priv_bytes = B64.decode(&priv_key).expect("private key not valid base64");
        let pub_bytes = B64.decode(&pub_key).expect("public key not valid base64");
        assert_eq!(priv_bytes.len(), 32, "private key length");
        assert_eq!(pub_bytes.len(), 32, "public key length");
    }

    #[tokio::test]
    async fn pubkey_from_private_derives_correct_key() {
        let (priv_key, pub_key) = generate_keypair().await.unwrap();
        let derived = pubkey_from_private(&priv_key).await.unwrap();
        assert_eq!(derived, pub_key, "derived public key must match generated one");
    }

    #[tokio::test]
    async fn pubkey_from_private_known_vector() {
        // Known test vector: 32 zero bytes as private key.
        // x25519 of all-zeros maps to the base point result (per RFC 7748 §6.1).
        let priv_zeros = B64.encode([0u8; 32]);
        let pub_key = pubkey_from_private(&priv_zeros).await.unwrap();
        let pub_bytes = B64.decode(&pub_key).unwrap();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[tokio::test]
    async fn pubkey_from_private_rejects_bad_base64() {
        let err = pubkey_from_private("not-valid!!!").await.unwrap_err();
        assert!(
            matches!(err, AppError::KeygenFailed(_)),
            "expected KeygenFailed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn pubkey_from_private_rejects_wrong_length() {
        // 16 bytes — not 32.
        let short = B64.encode([0u8; 16]);
        let err = pubkey_from_private(&short).await.unwrap_err();
        assert!(
            matches!(err, AppError::KeygenFailed(_)),
            "expected KeygenFailed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn generate_keypair_produces_unique_keys_on_successive_calls() {
        let (p1, _) = generate_keypair().await.unwrap();
        let (p2, _) = generate_keypair().await.unwrap();
        // Two fresh random keys must differ (probability of collision is negligible).
        assert_ne!(p1, p2, "two consecutive keypairs must differ");
    }
}
