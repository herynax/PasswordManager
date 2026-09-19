use crate::errors::Result;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

pub fn random_vec(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    random_array()
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    random_array()
}
