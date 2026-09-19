use crate::crypto::random::{NONCE_LEN, TAG_LEN};
use crate::errors::{Error, Result};

use super::format::{self, VaultHeader};

pub struct ParsedFile {
    bytes: Vec<u8>,
    pub header: VaultHeader,
    pub payload_nonce: [u8; NONCE_LEN],
    pub payload_total_len_minus_tag: usize,
}

impl ParsedFile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn payload_ciphertext_offset(&self) -> usize {
        self.header.header_len() + 8 + NONCE_LEN
    }

    pub fn payload_ciphertext(&self) -> &[u8] {
        &self.bytes[self.payload_ciphertext_offset()..]
    }

    pub fn slot_aad(&self, index: usize) -> &[u8] {
        &self.bytes[..format::slot_wrapped_dek_offset(index)]
    }

    pub fn payload_aad(&self) -> &[u8] {
        &self.bytes[..self.header.header_len()]
    }
}

pub fn parse_vault(bytes: Vec<u8>) -> Result<ParsedFile> {
    let (header, payload_nonce, payload_total_len) = {
        let parsed = format::parse(&bytes)?;
        let total = parsed.payload_total_len as usize;
        if parsed.payload_ciphertext.len() != total {
            return Err(Error::InvalidFormat("payload length mismatch"));
        }
        if total < TAG_LEN {
            return Err(Error::InvalidFormat("payload too small"));
        }
        (parsed.header.clone(), parsed.payload_nonce, total)
    };
    Ok(ParsedFile {
        bytes,
        header,
        payload_nonce,
        payload_total_len_minus_tag: payload_total_len - TAG_LEN,
    })
}

pub fn validate_vault(bytes: &[u8]) -> Result<()> {
    let parsed = format::parse(bytes)?;
    if parsed.header.slots.is_empty() {
        return Err(Error::InvalidFormat("vault has no key slots"));
    }
    Ok(())
}

pub fn vault_id_of(bytes: &[u8]) -> Result<[u8; 16]> {
    let parsed = format::parse(bytes)?;
    Ok(parsed.header.vault_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::{random_nonce, random_salt};
    use crate::vault::format::{self, Slot, SlotType, MAX_PAYLOAD_LEN, MAX_SLOT_COUNT};

    fn sample_slots() -> Vec<Slot> {
        vec![Slot {
            slot_type: SlotType::Passphrase,
            salt: random_salt().unwrap(),
            nonce: random_nonce().unwrap(),
            wrapped_dek: [0xCD; format::WRAPPED_DEK_LEN],
        }]
    }

    fn sample_file(payload_len: usize) -> Vec<u8> {
        let header = VaultHeader {
            vault_id: [0xAB; 16],
            kdf_params: crate::crypto::kdf::KdfParams::default(),
            slots: sample_slots(),
        };
        let mut bytes = format::encode_header(&header);
        bytes.extend_from_slice(&(payload_len as u64).to_be_bytes());
        bytes.extend_from_slice(&random_nonce().unwrap());
        bytes.extend(vec![0u8; payload_len]);
        bytes
    }

    #[test]
    fn parses_valid_file() {
        let len = 64 + TAG_LEN;
        let bytes = sample_file(len);
        let f = parse_vault(bytes).unwrap();
        assert_eq!(f.payload_total_len_minus_tag, 64);
        assert!(!f.slot_aad(0).is_empty());
        assert_eq!(
            f.payload_ciphertext().len() + f.payload_ciphertext_offset(),
            f.bytes().len()
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample_file(64);
        bytes[8] = 99;
        assert!(matches!(
            parse_vault(bytes),
            Err(Error::UnsupportedVersion(99, _))
        ));
    }

    #[test]
    fn rejects_bad_slot_count() {
        let header = VaultHeader {
            vault_id: [0xAB; 16],
            kdf_params: crate::crypto::kdf::KdfParams::default(),
            slots: sample_slots(),
        };
        let mut bytes = format::encode_header(&header);
        bytes[40] = 0;
        bytes[41] = 0;
        assert!(matches!(
            format::parse(&bytes),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn rejects_excessive_slot_count() {
        let header = VaultHeader {
            vault_id: [0xAB; 16],
            kdf_params: crate::crypto::kdf::KdfParams::default(),
            slots: sample_slots(),
        };
        let mut bytes = format::encode_header(&header);
        bytes[40] = 0;
        bytes[41] = MAX_SLOT_COUNT as u8 + 1;
        assert!(matches!(
            format::parse(&bytes),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn rejects_trailing_data() {
        let mut bytes = sample_file(64);
        bytes.push(0x00);
        assert!(parse_vault(bytes).is_err());
    }

    #[test]
    fn rejects_oversized_payload_decl() {
        let header = VaultHeader {
            vault_id: [0xAB; 16],
            kdf_params: crate::crypto::kdf::KdfParams::default(),
            slots: sample_slots(),
        };
        let mut bytes = format::encode_header(&header);
        bytes.extend_from_slice(&(MAX_PAYLOAD_LEN + 1).to_be_bytes());
        bytes.extend_from_slice(&random_nonce().unwrap());
        assert!(format::parse(&bytes).is_err());
    }
}
