use passman::crypto::aead;
use passman::crypto::kdf::{self, KdfParams};
use passman::crypto::keys;
use passman::crypto::random::{self, NONCE_LEN, SALT_LEN, TAG_LEN};
use passman::{Error, Result};

fn full_encrypt_flow(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let kek = kdf::derive_key(passphrase, salt, &KdfParams::default())?;
    aead::encrypt(kek.as_ref(), nonce, aad, payload)
}

fn full_decrypt_flow(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let kek = kdf::derive_key(passphrase, salt, &KdfParams::default())?;
    let pt = aead::decrypt(kek.as_ref(), nonce, aad, ciphertext)?;
    Ok(pt.to_vec())
}

#[test]
fn integration_full_flow() {
    let passphrase = b"correct horse battery staple".as_slice();
    let salt = [0x42u8; SALT_LEN];
    let nonce = [0x24u8; NONCE_LEN];
    let aad = b"passman-format-v1";
    let payload = b"username+password+totp";

    let ct = full_encrypt_flow(passphrase, &salt, &nonce, aad, payload).unwrap();
    let pt = full_decrypt_flow(passphrase, &salt, &nonce, aad, &ct).unwrap();
    assert_eq!(pt, payload);
}

#[test]
fn integration_wrong_master_secret() {
    let passphrase = b"correct horse battery staple".as_slice();
    let salt = [0x42u8; SALT_LEN];
    let nonce = [0x24u8; NONCE_LEN];
    let ct = full_encrypt_flow(passphrase, &salt, &nonce, b"aad", b"payload").unwrap();
    let err = full_decrypt_flow(b"wrong passphrase", &salt, &nonce, b"aad", &ct);
    assert_eq!(err, Err(Error::Authentication));
}

#[test]
fn integration_modified_ciphertext() {
    let kek = kdf::derive_key(b"pw", &[0x42u8; SALT_LEN], &KdfParams::default()).unwrap();
    let nonce = [0x24u8; NONCE_LEN];
    let msg = b"the entire vault payload sits here encrypted";
    let mut ct = aead::encrypt(kek.as_ref(), &nonce, b"aad", msg).unwrap();
    ct[0] ^= 0x80;
    assert_eq!(
        aead::decrypt(kek.as_ref(), &nonce, b"aad", &ct),
        Err(Error::Authentication)
    );
}

#[test]
fn integration_modified_salt_undetected_key_mismatch() {
    let pass = b"pw".as_slice();
    let salt = [0x42u8; SALT_LEN];
    let nonce = [0x24u8; NONCE_LEN];
    let ct = full_encrypt_flow(pass, &salt, &nonce, b"aad", b"payload").unwrap();
    let mut bad_salt = salt;
    bad_salt[0] ^= 0x01;
    assert_eq!(
        full_decrypt_flow(pass, &bad_salt, &nonce, b"aad", &ct),
        Err(Error::Authentication)
    );
}

#[test]
fn integration_modified_kdf_params() {
    let kek_default = kdf::derive_key(b"pw", &[0x42u8; SALT_LEN], &KdfParams::default()).unwrap();
    let nonce = [0x24u8; NONCE_LEN];
    let ct = aead::encrypt(kek_default.as_ref(), &nonce, b"aad", b"payload").unwrap();

    let weak = KdfParams::new(kdf::MIN_M_COST, kdf::MIN_T_COST, kdf::MIN_P_COST);
    let kek_weak = kdf::derive_key(b"pw", &[0x42u8; SALT_LEN], &weak).unwrap();
    assert_eq!(
        aead::decrypt(kek_weak.as_ref(), &nonce, b"aad", &ct),
        Err(Error::Authentication)
    );
}

#[test]
fn integration_different_kek_per_salt() {
    let s1 = [0x01u8; SALT_LEN];
    let s2 = [0x02u8; SALT_LEN];
    let k1 = kdf::derive_key(b"pw", &s1, &KdfParams::default()).unwrap();
    let k2 = kdf::derive_key(b"pw", &s2, &KdfParams::default()).unwrap();
    assert_ne!(k1.as_ref(), k2.as_ref());
}

#[test]
fn integration_dek_wrapping_envelope() {
    let master = b"master secret".as_slice();
    let salt = random::random_salt().unwrap();
    let kek = kdf::derive_key(master, &salt, &KdfParams::default()).unwrap();
    let dek = keys::generate_dek().unwrap();
    let slot_nonce = random::random_nonce().unwrap();
    let wrapped = aead::encrypt(kek.as_ref(), &slot_nonce, b"header-aad", dek.as_ref()).unwrap();
    assert_eq!(wrapped.len(), dek.len() + TAG_LEN);

    let unwrapped = aead::decrypt(kek.as_ref(), &slot_nonce, b"header-aad", &wrapped).unwrap();
    assert_eq!(&*unwrapped, &*dek);
}

#[test]
fn integration_generated_nonces_do_not_collide() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let n = random::random_nonce().unwrap();
        assert!(seen.insert(n), "nonce collision");
    }
}
