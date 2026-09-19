use crate::crypto::kdf::KdfParams;
use crate::crypto::random::{KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::errors::{Error, Result};

pub const MAGIC: [u8; 8] = *b"PAMVLT01";
pub const FORMAT_VERSION_MAJOR: u8 = 1;
pub const FORMAT_VERSION_MINOR: u8 = 0;

pub const KDF_ID_ARGON2ID: u8 = 1;
pub const AEAD_ID_XCHACHA20_POLY1305: u8 = 1;

pub const VAULT_ID_LEN: usize = 16;

pub const VAULT_ID_OFFSET: usize = 10;
pub const KDF_ID_OFFSET: usize = 26;
pub const AEAD_ID_OFFSET: usize = 27;
pub const M_COST_OFFSET: usize = 28;
pub const T_COST_OFFSET: usize = 32;
pub const P_COST_OFFSET: usize = 36;
pub const SLOT_COUNT_OFFSET: usize = 40;

pub const SLOT_TYPE_PASSPHRASE: u8 = 0x01;
pub const SLOT_TYPE_RECOVERY: u8 = 0x02;
pub const SLOT_TYPE_HARDWARE: u8 = 0x03;

pub const SLOT_HEADER_LEN: usize = 1 + 1 + SALT_LEN + NONCE_LEN;
pub const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
pub const SLOT_LEN: usize = SLOT_HEADER_LEN + WRAPPED_DEK_LEN;

pub const FIXED_HEADER_LEN: usize = 8 + 2 + VAULT_ID_LEN + 1 + 1 + 4 + 4 + 4 + 2;

pub const MAX_SLOT_COUNT: usize = 8;
pub const MAX_PAYLOAD_LEN: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SlotType {
    Passphrase = SLOT_TYPE_PASSPHRASE,
    Recovery = SLOT_TYPE_RECOVERY,
    Hardware = SLOT_TYPE_HARDWARE,
}

impl SlotType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            SLOT_TYPE_PASSPHRASE => Ok(Self::Passphrase),
            SLOT_TYPE_RECOVERY => Ok(Self::Recovery),
            SLOT_TYPE_HARDWARE => Ok(Self::Hardware),
            _ => Err(Error::InvalidFormat("unknown key slot type")),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub slot_type: SlotType,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
}

#[derive(Clone, Debug)]
pub struct VaultHeader {
    pub vault_id: [u8; VAULT_ID_LEN],
    pub kdf_params: KdfParams,
    pub slots: Vec<Slot>,
}

impl VaultHeader {
    pub fn header_len(&self) -> usize {
        FIXED_HEADER_LEN + self.slots.len() * SLOT_LEN
    }

    pub fn slot_wrapped_dek_offset(&self, index: usize) -> usize {
        slot_wrapped_dek_offset(index)
    }
}

pub fn slot_wrapped_dek_offset(index: usize) -> usize {
    FIXED_HEADER_LEN + index * SLOT_LEN + SLOT_HEADER_LEN
}

#[derive(Clone, Debug)]
pub struct ParsedVault<'a> {
    pub header: VaultHeader,
    pub payload_nonce: [u8; NONCE_LEN],
    pub payload_total_len: u64,
    pub payload_ciphertext: &'a [u8],
}

pub fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn read_u32_be(buf: &[u8], at: usize) -> Result<u32> {
    let bytes = buf
        .get(at..at + 4)
        .ok_or(Error::InvalidFormat("truncated header"))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

pub fn read_u64_be(buf: &[u8], at: usize) -> Result<u64> {
    let bytes = buf
        .get(at..at + 8)
        .ok_or(Error::InvalidFormat("truncated header"))?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

pub fn encode_header(header: &VaultHeader) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.header_len());
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION_MAJOR);
    out.push(FORMAT_VERSION_MINOR);
    out.extend_from_slice(&header.vault_id);
    out.push(KDF_ID_ARGON2ID);
    out.push(AEAD_ID_XCHACHA20_POLY1305);
    write_u32_be(&mut out, header.kdf_params.m_cost);
    write_u32_be(&mut out, header.kdf_params.t_cost);
    write_u32_be(&mut out, header.kdf_params.p_cost);
    let slot_count = header.slots.len() as u16;
    out.extend_from_slice(&slot_count.to_be_bytes());
    for slot in &header.slots {
        out.push(slot.slot_type.to_u8());
        out.push(SALT_LEN as u8);
        out.extend_from_slice(&slot.salt);
        out.extend_from_slice(&slot.nonce);
        out.extend_from_slice(&slot.wrapped_dek);
    }
    out
}

pub fn parse(bytes: &[u8]) -> Result<ParsedVault<'_>> {
    if bytes.len() < FIXED_HEADER_LEN {
        return Err(Error::InvalidFormat("file too small"));
    }
    if bytes[0..8] != MAGIC {
        return Err(Error::InvalidFormat("bad magic"));
    }
    let major = bytes[8];
    let minor = bytes[9];
    if major != FORMAT_VERSION_MAJOR {
        return Err(Error::UnsupportedVersion(major, minor));
    }
    if bytes[KDF_ID_OFFSET] != KDF_ID_ARGON2ID {
        return Err(Error::UnsupportedKdf(bytes[KDF_ID_OFFSET]));
    }
    if bytes[AEAD_ID_OFFSET] != AEAD_ID_XCHACHA20_POLY1305 {
        return Err(Error::UnsupportedCipher(bytes[AEAD_ID_OFFSET]));
    }

    let vault_id: [u8; VAULT_ID_LEN] = bytes[VAULT_ID_OFFSET..VAULT_ID_OFFSET + VAULT_ID_LEN]
        .try_into()
        .map_err(|_| Error::InvalidFormat("truncated vault_id"))?;

    let kdf_params = KdfParams::new(
        read_u32_be(bytes, M_COST_OFFSET)?,
        read_u32_be(bytes, T_COST_OFFSET)?,
        read_u32_be(bytes, P_COST_OFFSET)?,
    );
    kdf_params.validate()?;

    let slot_count = bytes
        .get(SLOT_COUNT_OFFSET..SLOT_COUNT_OFFSET + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(Error::InvalidFormat("truncated slot count"))? as usize;
    if slot_count == 0 || slot_count > MAX_SLOT_COUNT {
        return Err(Error::InvalidFormat("invalid slot count"));
    }

    let mut header = VaultHeader {
        vault_id,
        kdf_params,
        slots: Vec::with_capacity(slot_count),
    };
    let slots_start = FIXED_HEADER_LEN;
    for i in 0..slot_count {
        let at = slots_start + i * SLOT_LEN;
        let slot_type = SlotType::from_u8(
            *bytes
                .get(at)
                .ok_or(Error::InvalidFormat("truncated slot"))?,
        )?;
        let salt_len = *bytes
            .get(at + 1)
            .ok_or(Error::InvalidFormat("truncated slot"))? as usize;
        if salt_len != SALT_LEN {
            return Err(Error::InvalidFormat("invalid slot salt length"));
        }
        let salt: [u8; SALT_LEN] = bytes
            .get(at + 2..at + 2 + SALT_LEN)
            .ok_or(Error::InvalidFormat("truncated slot salt"))?
            .try_into()
            .map_err(|_| Error::InvalidFormat("truncated slot salt"))?;
        let nonce: [u8; NONCE_LEN] = bytes
            .get(at + 2 + SALT_LEN..at + 2 + SALT_LEN + NONCE_LEN)
            .ok_or(Error::InvalidFormat("truncated slot nonce"))?
            .try_into()
            .map_err(|_| Error::InvalidFormat("truncated slot nonce"))?;
        let wrapped_start = at + SLOT_HEADER_LEN;
        let wrapped_dek: [u8; WRAPPED_DEK_LEN] = bytes
            .get(wrapped_start..wrapped_start + WRAPPED_DEK_LEN)
            .ok_or(Error::InvalidFormat("truncated wrapped DEK"))?
            .try_into()
            .map_err(|_| Error::InvalidFormat("truncated wrapped DEK"))?;
        header.slots.push(Slot {
            slot_type,
            salt,
            nonce,
            wrapped_dek,
        });
    }

    let payload_len_offset = header.header_len();
    let payload_total_len = read_u64_be(bytes, payload_len_offset)?;
    if payload_total_len < TAG_LEN as u64 {
        return Err(Error::InvalidFormat("payload too small"));
    }
    if payload_total_len > MAX_PAYLOAD_LEN {
        return Err(Error::InvalidFormat("payload too large"));
    }
    let nonce_offset = payload_len_offset + 8;
    let payload_nonce: [u8; NONCE_LEN] = bytes
        .get(nonce_offset..nonce_offset + NONCE_LEN)
        .ok_or(Error::InvalidFormat("truncated payload nonce"))?
        .try_into()
        .map_err(|_| Error::InvalidFormat("truncated payload nonce"))?;
    let ct_start = nonce_offset + NONCE_LEN;
    let ct_end = ct_start + payload_total_len as usize;
    let payload_ciphertext = bytes
        .get(ct_start..ct_end)
        .ok_or(Error::InvalidFormat("truncated payload"))?;
    if ct_end != bytes.len() {
        return Err(Error::InvalidFormat("trailing data after payload"));
    }

    Ok(ParsedVault {
        header,
        payload_nonce,
        payload_total_len,
        payload_ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::{random_nonce, random_salt, random_vec};

    fn sample_header() -> VaultHeader {
        VaultHeader {
            vault_id: [0xAB; VAULT_ID_LEN],
            kdf_params: KdfParams::default(),
            slots: vec![Slot {
                slot_type: SlotType::Passphrase,
                salt: random_salt().unwrap(),
                nonce: random_nonce().unwrap(),
                wrapped_dek: [0xCD; WRAPPED_DEK_LEN],
            }],
        }
    }

    fn full_file(header: &VaultHeader, payload: &[u8]) -> Vec<u8> {
        let mut bytes = encode_header(header);
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&random_nonce().unwrap());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn header_roundtrip() {
        let header = sample_header();
        let bytes = full_file(&header, &random_vec(16).unwrap());
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.header.vault_id, header.vault_id);
        assert_eq!(parsed.header.kdf_params, header.kdf_params);
        assert_eq!(parsed.header.slots.len(), 1);
        assert_eq!(parsed.header.slots[0].slot_type, SlotType::Passphrase);
        assert_eq!(parsed.header.slots[0].salt, header.slots[0].salt);
        assert_eq!(parsed.header.slots[0].nonce, header.slots[0].nonce);
        assert_eq!(
            parsed.header.slots[0].wrapped_dek,
            header.slots[0].wrapped_dek
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let header = sample_header();
        let mut bytes = full_file(&header, &random_vec(16).unwrap());
        bytes[0] ^= 0xFF;
        assert!(matches!(
            parse(&bytes),
            Err(Error::InvalidFormat("bad magic"))
        ));
    }

    #[test]
    fn rejects_unsupported_major_version() {
        let header = sample_header();
        let mut bytes = full_file(&header, &random_vec(16).unwrap());
        bytes[8] = 99;
        assert!(matches!(
            parse(&bytes),
            Err(Error::UnsupportedVersion(99, _))
        ));
    }

    #[test]
    fn rejects_unsupported_kdf() {
        let header = sample_header();
        let mut bytes = full_file(&header, &random_vec(16).unwrap());
        bytes[KDF_ID_OFFSET] = 42;
        assert!(matches!(parse(&bytes), Err(Error::UnsupportedKdf(42))));
    }

    #[test]
    fn rejects_unsupported_cipher() {
        let header = sample_header();
        let mut bytes = full_file(&header, &random_vec(16).unwrap());
        bytes[AEAD_ID_OFFSET] = 42;
        assert!(matches!(parse(&bytes), Err(Error::UnsupportedCipher(42))));
    }

    #[test]
    fn rejects_weak_kdf_params_in_file() {
        let header = sample_header();
        let mut bytes = full_file(&header, &random_vec(16).unwrap());
        let weak = 4u32.to_be_bytes();
        bytes[M_COST_OFFSET..M_COST_OFFSET + 4].copy_from_slice(&weak);
        assert!(matches!(parse(&bytes), Err(Error::InvalidKdfParameters)));
    }

    #[test]
    fn rejects_truncated_payload() {
        let header = sample_header();
        let mut bytes = encode_header(&header);
        let payload = random_vec(64).unwrap();
        let nonce = random_nonce().unwrap();
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&payload);
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(parse(&bytes), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn rejects_trailing_data() {
        let header = sample_header();
        let mut bytes = encode_header(&header);
        let payload = random_vec(64).unwrap();
        let nonce = random_nonce().unwrap();
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&payload);
        bytes.push(0x00);
        assert!(matches!(
            parse(&bytes),
            Err(Error::InvalidFormat("trailing data after payload"))
        ));
    }

    #[test]
    fn slot_offset_matches_encoding() {
        let header = sample_header();
        let bytes = encode_header(&header);
        let expected = FIXED_HEADER_LEN + SLOT_HEADER_LEN;
        assert_eq!(header.slot_wrapped_dek_offset(0), expected);
        assert_eq!(
            &bytes[expected..expected + WRAPPED_DEK_LEN],
            &header.slots[0].wrapped_dek
        );
    }
}
