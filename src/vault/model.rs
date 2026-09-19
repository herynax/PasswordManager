use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::kdf::{derive_key, KdfParams};
use crate::crypto::keys::generate_dek;
use crate::crypto::random::{random_array, random_nonce, random_salt, KEY_LEN};
use crate::errors::{Error, Result};

use super::format::{
    self, encode_header, Slot, SlotType, VaultHeader, VAULT_ID_LEN, WRAPPED_DEK_LEN,
};
use super::parse::{self, ParsedFile};
use super::storage;

pub struct VaultFile {
    parsed: ParsedFile,
}

impl VaultFile {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = storage::read_vault(path)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        parse::validate_vault(&bytes)?;
        let parsed = parse::parse_vault(bytes)?;
        Ok(VaultFile { parsed })
    }

    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.parsed.header.vault_id
    }

    pub fn slot_count(&self) -> usize {
        self.parsed.header.slots.len()
    }

    pub fn has_passphrase_slot(&self) -> bool {
        self.parsed
            .header
            .slots
            .iter()
            .any(|s| s.slot_type == SlotType::Passphrase)
    }

    pub fn unlock(&self, passphrase: &[u8]) -> Result<Unlocked> {
        for (i, slot) in self.parsed.header.slots.iter().enumerate() {
            if slot.slot_type != SlotType::Passphrase {
                continue;
            }
            let kek = match derive_key(passphrase, &slot.salt, &self.parsed.header.kdf_params) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let wrapped_aad = self.parsed.slot_aad(i);
            if let Ok(wrapped_dek) =
                aead::decrypt(&*kek, &slot.nonce, wrapped_aad, &slot.wrapped_dek)
            {
                let mut dek = Zeroizing::new([0u8; KEY_LEN]);
                dek.copy_from_slice(&wrapped_dek);
                let payload_aad = self.parsed.payload_aad();
                let content = aead::decrypt(
                    &*dek,
                    &self.parsed.payload_nonce,
                    payload_aad,
                    self.parsed.payload_ciphertext(),
                )?;
                return Ok(Unlocked {
                    header: self.parsed.header.clone(),
                    dek,
                    content,
                });
            }
        }
        Err(Error::Authentication)
    }
}

pub struct Unlocked {
    header: VaultHeader,
    dek: Zeroizing<[u8; KEY_LEN]>,
    content: Zeroizing<Vec<u8>>,
}

impl Unlocked {
    pub fn create(passphrase: &[u8], kdf_params: &KdfParams, content: Vec<u8>) -> Result<Self> {
        let vault_id: [u8; VAULT_ID_LEN] = random_array()?;
        let dek = generate_dek()?;
        let salt = random_salt()?;
        let slot_nonce = random_nonce()?;
        let kek = derive_key(passphrase, &salt, kdf_params)?;

        // Build the header with the slot in place (wrapped DEK zeroed as a
        // placeholder). The wrapping AAD covers everything up to the slot's
        // wrapped-DEK field: magic, version, vault_id, KDF/aead ids, params,
        // slot count, and the slot's own type/salt/nonce. This binds the
        // wrapped DEK to the vault identity and slot layout.
        let mut slots = vec![Slot {
            slot_type: SlotType::Passphrase,
            salt,
            nonce: slot_nonce,
            wrapped_dek: [0u8; WRAPPED_DEK_LEN],
        }];
        let mut header = VaultHeader {
            vault_id,
            kdf_params: *kdf_params,
            slots,
        };
        let wrapped_offset = format::slot_wrapped_dek_offset(0);
        let header_bytes = encode_header(&header);
        let wrapped_aad = &header_bytes[..wrapped_offset];

        let wrapped = aead::encrypt(&*kek, &slot_nonce, wrapped_aad, &*dek)?;
        if wrapped.len() != WRAPPED_DEK_LEN {
            return Err(Error::Crypto);
        }
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] =
            wrapped.as_slice().try_into().map_err(|_| Error::Crypto)?;

        header.slots[0].wrapped_dek = wrapped_dek;
        slots = header.slots;
        let header = VaultHeader {
            vault_id,
            kdf_params: *kdf_params,
            slots,
        };

        Ok(Unlocked {
            header,
            dek,
            content: Zeroizing::new(content),
        })
    }

    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.header.vault_id
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn set_content(&mut self, content: Vec<u8>) {
        self.content = Zeroizing::new(content);
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let header_bytes = encode_header(&self.header);
        let payload_aad = &header_bytes[..self.header.header_len()];
        let payload_nonce = random_nonce()?;
        let payload_ct = aead::encrypt(&*self.dek, &payload_nonce, payload_aad, &self.content)?;

        let mut out = header_bytes;
        out.extend_from_slice(&(payload_ct.len() as u64).to_be_bytes());
        out.extend_from_slice(&payload_nonce);
        out.extend_from_slice(&payload_ct);
        Ok(out)
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let bytes = self.serialize()?;
        storage::write_vault(path, &bytes)
    }

    pub fn lock(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KdfParams {
        KdfParams::default()
    }

    #[test]
    fn create_serialize_unlock_roundtrip() {
        let v = Unlocked::create(b"hunter2", &kdf(), b"secret-content".to_vec()).unwrap();
        assert_eq!(v.content(), b"secret-content");
        assert_eq!(v.vault_id().len(), VAULT_ID_LEN);

        let encoded = v.serialize().unwrap();
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert_eq!(file.vault_id(), v.vault_id());
        assert_eq!(file.slot_count(), 1);
        assert!(file.has_passphrase_slot());

        let mut unlocked = file.unlock(b"hunter2").unwrap();
        assert_eq!(unlocked.content(), b"secret-content");

        unlocked.set_content(b"updated!".to_vec());
        assert_eq!(unlocked.content(), b"updated!");
    }

    #[test]
    fn wrong_passphrase_fails_lockstep() {
        let v = Unlocked::create(b"right", &kdf(), b"data".to_vec()).unwrap();
        let encoded = v.serialize().unwrap();
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert!(matches!(file.unlock(b"wrong"), Err(Error::Authentication)));
        assert!(matches!(file.unlock(b""), Err(Error::Authentication)));
    }

    #[test]
    fn lock_consumes_and_drops() {
        let v = Unlocked::create(b"pw", &kdf(), b"data".to_vec()).unwrap();
        v.lock();
    }

    #[test]
    fn reject_tampered_payload() {
        let v = Unlocked::create(b"pw", &kdf(), b"important secret data".to_vec()).unwrap();
        let mut encoded = v.serialize().unwrap();
        let n = encoded.len();
        encoded[n - 20] ^= 0x01;
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert!(matches!(file.unlock(b"pw"), Err(Error::Authentication)));
    }
}
