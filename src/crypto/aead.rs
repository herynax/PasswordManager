use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::Key;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use zeroize::Zeroizing;

use crate::crypto::random::{NONCE_LEN, TAG_LEN};
use crate::errors::{Error, Result};

pub fn encrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Crypto);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| -> Error { e.into() })
}

pub fn decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 {
        return Err(Error::Crypto);
    }
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Authentication);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::{random_array, random_nonce};

    fn test_key() -> [u8; 32] {
        [0x11u8; 32]
    }

    #[test]
    fn roundtrip_with_associated_data() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let aad = b"vault-header-v1";
        let msg = b"the password is a secret";
        let ct = encrypt(&key, &nonce, aad, msg).unwrap();
        assert_eq!(ct.len(), msg.len() + TAG_LEN);
        let pt = decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(&*pt, msg);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        let pt = decrypt(&key, &nonce, b"", &ct).unwrap();
        assert_eq!(&*pt, b"");
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let wrong = [0x33u8; 32];
        let nonce = [0x22u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"payload").unwrap();
        assert_eq!(
            decrypt(&wrong, &nonce, b"aad", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn modified_ciphertext_fails() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let msg = b"payload with enough length";
        let mut ct = encrypt(&key, &nonce, b"aad", msg).unwrap();
        let idx = ct.len() / 2;
        ct[idx] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn modified_nonce_fails() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"payload").unwrap();
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &bad_nonce, b"aad", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn modified_aad_fails() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"payload").unwrap();
        assert_eq!(
            decrypt(&key, &nonce, b"different-aad", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = test_key();
        let nonce = [0x22u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"aad", b"payload").unwrap();
        ct.truncate(ct.len() - 1);
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &ct),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn random_key_and_nonce_roundtrip() {
        let key: [u8; 32] = random_array().unwrap();
        let nonce = random_nonce().unwrap();
        let msg = b"generated from CSPRNG";
        let ct = encrypt(&key, &nonce, b"hdr", msg).unwrap();
        let pt = decrypt(&key, &nonce, b"hdr", &ct).unwrap();
        assert_eq!(&*pt, msg);
    }

    #[test]
    fn nonces_are_unique() {
        let n1 = random_nonce().unwrap();
        let n2 = random_nonce().unwrap();
        let n3 = random_nonce().unwrap();
        assert_ne!(n1, n2);
        assert_ne!(n2, n3);
        assert_ne!(n1, n3);
    }

    #[test]
    fn salts_are_unique() {
        let s1 = crate::crypto::random::random_salt().unwrap();
        let s2 = crate::crypto::random::random_salt().unwrap();
        assert_ne!(s1, s2);
    }
}
