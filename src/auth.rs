use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Generates a 32-byte random nonce for challenge-response auth.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = rand::thread_rng();
    nonce[..8].copy_from_slice(&ts.to_be_bytes());
    rng.fill_bytes(&mut nonce[8..]);
    nonce
}

/// Computes expected HMAC for auth verification.
/// key = password_sha256, data = server nonce
pub fn compute_expected_hmac(password_sha256: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(password_sha256)
        .expect("HMAC can take key of any size");
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

/// Verifies client auth response.
pub fn verify_auth(client_hmac: &[u8; 32], password_sha256: &[u8], nonce: &[u8]) -> bool {
    let expected = compute_expected_hmac(password_sha256, nonce);
    client_hmac == &expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_verify() {
        let key = b"test_password_sha256!!!!!!!!!!!!!!";
        let nonce = generate_nonce();
        let hmac = compute_expected_hmac(key, &nonce);
        assert!(verify_auth(&hmac, key, &nonce));
    }

    #[test]
    fn test_hmac_wrong_key() {
        let key = b"correct_key_sha256!!!!!!!!!!!!!!";
        let wrong = b"wrong_key_sha256!!!!!!!!!!!!!!!";
        let nonce = generate_nonce();
        let hmac = compute_expected_hmac(key, &nonce);
        assert!(!verify_auth(&hmac, wrong, &nonce));
    }
}
