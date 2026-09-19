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
use super::payload::{self, Entry, Payload};
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
                let entries = payload::decode(&content)?;
                return Ok(Unlocked {
                    header: self.parsed.header.clone(),
                    dek,
                    payload: entries,
                });
            }
        }
        Err(Error::Authentication)
    }
}

pub struct Unlocked {
    header: VaultHeader,
    dek: Zeroizing<[u8; KEY_LEN]>,
    payload: Payload,
}

impl Unlocked {
    pub fn create(passphrase: &[u8], kdf_params: &KdfParams) -> Result<Self> {
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
        let slots = vec![Slot {
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
        let header = VaultHeader {
            vault_id,
            kdf_params: *kdf_params,
            slots: header.slots,
        };

        Ok(Unlocked {
            header,
            dek,
            payload: Payload::new(),
        })
    }

    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.header.vault_id
    }

    pub fn entry_count(&self) -> usize {
        self.payload.entries.len()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.payload.entries
    }

    pub fn get_entry(&self, id: &str) -> Option<&Entry> {
        self.payload.entries.iter().find(|e| e.id == id)
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<()> {
        if self.payload.entries.len() >= payload::MAX_ENTRIES {
            return Err(Error::InvalidFormat("too many entries"));
        }
        if entry.tags.len() > payload::MAX_TAGS {
            return Err(Error::InvalidFormat("too many tags"));
        }
        if self.payload.entries.iter().any(|e| e.id == entry.id) {
            return Err(Error::InvalidFormat("duplicate entry id"));
        }
        self.payload.entries.push(entry);
        Ok(())
    }

    pub fn update_entry(&mut self, id: &str, f: impl FnOnce(&mut Entry)) -> Result<()> {
        let entry = self
            .payload
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::InvalidFormat("entry not found"))?;
        f(entry);
        entry.updated_at = payload::now_unix();
        Ok(())
    }

    pub fn delete_entry(&mut self, id: &str) -> bool {
        let before = self.payload.entries.len();
        self.payload.entries.retain(|e| e.id != id);
        self.payload.entries.len() != before
    }

    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query_lower = query.to_lowercase();
        self.payload
            .entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&query_lower)
                    || e.tags.iter().any(|t| t.to_lowercase() == query_lower)
            })
            .collect()
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let content = payload::encode(&self.payload)?;
        let header_bytes = encode_header(&self.header);
        let payload_aad = &header_bytes[..self.header.header_len()];
        let payload_nonce = random_nonce()?;
        let payload_ct = aead::encrypt(&*self.dek, &payload_nonce, payload_aad, &content)?;

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

impl Unlocked {
    /// Rewraps the existing DEK under a fresh KEK derived from `new_passphrase`
    /// in-place, replacing the single passphrase slot. Used by `pass change`.
    pub fn change_passphrase(&mut self, new_passphrase: &[u8]) -> Result<()> {
        let idx = self
            .header
            .slots
            .iter()
            .position(|s| s.slot_type == SlotType::Passphrase)
            .ok_or(Error::NoUsableSlot)?;
        assert_eq!(
            self.header.slots.len(),
            1,
            "MVP supports a single passphrase slot"
        );

        let salt = random_salt()?;
        let slot_nonce = random_nonce()?;
        let kek = derive_key(new_passphrase, &salt, &self.header.kdf_params)?;

        // Build a clone with the fresh salt/nonce and an empty placeholder.
        let mut new_slot = Slot {
            slot_type: SlotType::Passphrase,
            salt,
            nonce: slot_nonce,
            wrapped_dek: [0u8; WRAPPED_DEK_LEN],
        };
        let mut new_header = self.header.clone();
        new_header.slots[idx] = new_slot.clone();
        let wrapped_offset = format::slot_wrapped_dek_offset(idx);
        let header_bytes = encode_header(&new_header);
        let wrapped_aad = &header_bytes[..wrapped_offset];

        let wrapped = aead::encrypt(&*kek, &slot_nonce, wrapped_aad, &*self.dek)?;
        if wrapped.len() != WRAPPED_DEK_LEN {
            return Err(Error::Crypto);
        }
        new_slot.wrapped_dek = wrapped.as_slice().try_into().map_err(|_| Error::Crypto)?;
        new_header.slots[idx] = new_slot;
        self.header = new_header;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::payload::{EntryBody, LoginData};

    fn kdf() -> KdfParams {
        KdfParams::default()
    }

    fn login(title: &str, user: &str, pw: &str) -> Entry {
        Entry {
            id: "00000000-0000-4000-8000-000000000000".to_string(),
            title: title.to_string(),
            tags: vec![],
            created_at: payload::now_unix(),
            updated_at: payload::now_unix(),
            body: EntryBody::Login(LoginData {
                username: user.to_string(),
                password: pw.to_string(),
                url: String::new(),
            }),
        }
    }

    #[test]
    fn create_serialize_unlock_roundtrip() {
        let mut v = Unlocked::create(b"hunter2", &kdf()).unwrap();
        assert_eq!(v.vault_id().len(), VAULT_ID_LEN);

        v.add_entry(login("GitHub", "octocat", "s3cret")).unwrap();
        let encoded = v.serialize().unwrap();
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert_eq!(file.vault_id(), v.vault_id());
        assert_eq!(file.slot_count(), 1);
        assert!(file.has_passphrase_slot());

        let unlocked = file.unlock(b"hunter2").unwrap();
        assert_eq!(unlocked.entry_count(), 1);
        let e = unlocked
            .get_entry("00000000-0000-4000-8000-000000000000")
            .unwrap();
        match &e.body {
            EntryBody::Login(l) => assert_eq!(l.password, "s3cret"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn wrong_passphrase_fails_lockstep() {
        let v = Unlocked::create(b"right", &kdf()).unwrap();
        let encoded = v.serialize().unwrap();
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert!(matches!(file.unlock(b"wrong"), Err(Error::Authentication)));
        assert!(matches!(file.unlock(b""), Err(Error::Authentication)));
    }

    #[test]
    fn crud_lifecycle() {
        let mut v = Unlocked::create(b"pw", &kdf()).unwrap();
        let id = "11111111-1111-4111-8111-111111111111";
        let mut e = login("Example", "alice", "pw1");
        e.id = id.to_string();
        v.add_entry(e).unwrap();
        assert_eq!(v.entry_count(), 1);

        v.update_entry(id, |e| {
            if let EntryBody::Login(l) = &mut e.body {
                l.password = "pw2".to_string();
            }
        })
        .unwrap();

        match &v.get_entry(id).unwrap().body {
            EntryBody::Login(l) => assert_eq!(l.password, "pw2"),
            _ => panic!("wrong type"),
        }

        assert!(v.delete_entry(id));
        assert!(!v.delete_entry(id));
        assert_eq!(v.entry_count(), 0);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut v = Unlocked::create(b"pw", &kdf()).unwrap();
        let e = login("A", "a", "p");
        v.add_entry(e).unwrap();
        let dup = login("B", "b", "q");
        assert!(matches!(
            v.add_entry(dup),
            Err(Error::InvalidFormat("duplicate entry id"))
        ));
    }

    #[test]
    fn search_matches_title_and_tags() {
        let mut v = Unlocked::create(b"pw", &kdf()).unwrap();
        let mut e = login("GitHub", "octocat", "p");
        e.id = "00000000-0000-4000-8000-000000000001".to_string();
        e.tags = vec!["dev".to_string()];
        v.add_entry(e).unwrap();
        let mut n = login("Bank", "alice", "p");
        n.id = "00000000-0000-4000-8000-000000000002".to_string();
        n.tags = vec!["finance".to_string()];
        v.add_entry(n).unwrap();

        assert_eq!(v.search("github").len(), 1);
        assert_eq!(v.search("DEV").len(), 1);
        assert_eq!(v.search("nothing").len(), 0);
    }

    #[test]
    fn lock_consumes_and_drops() {
        let v = Unlocked::create(b"pw", &kdf()).unwrap();
        v.lock();
    }

    #[test]
    fn reject_tampered_payload() {
        let mut v = Unlocked::create(b"pw", &kdf()).unwrap();
        v.add_entry(login("Secret", "u", "p")).unwrap();
        let mut encoded = v.serialize().unwrap();
        let n = encoded.len();
        encoded[n - 20] ^= 0x01;
        let file = VaultFile::from_bytes(encoded).unwrap();
        assert!(matches!(file.unlock(b"pw"), Err(Error::Authentication)));
    }
}
