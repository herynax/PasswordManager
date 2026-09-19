use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::crypto::random::KEY_LEN;
use crate::errors::{Error, Result};

pub const DEFAULT_M_COST: u32 = 65_536;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

pub const MIN_M_COST: u32 = 19_456;
pub const MIN_T_COST: u32 = 2;
pub const MIN_P_COST: u32 = 1;

pub const MAX_M_COST: u32 = 4_194_304;
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.m_cost < MIN_M_COST || self.m_cost > MAX_M_COST {
            return Err(Error::InvalidKdfParameters);
        }
        if self.t_cost < MIN_T_COST || self.t_cost > MAX_T_COST {
            return Err(Error::InvalidKdfParameters);
        }
        if self.p_cost < MIN_P_COST || self.p_cost > MAX_P_COST {
            return Err(Error::InvalidKdfParameters);
        }
        if self.m_cost < 8 * self.p_cost {
            return Err(Error::InvalidKdfParameters);
        }
        Ok(())
    }

    pub fn to_argon2_params(&self) -> Result<Params> {
        self.validate()?;
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| Error::InvalidKdfParameters)
    }
}

pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if salt.len() < 8 {
        return Err(Error::InvalidKdfParameters);
    }
    let argon_params = params.to_argon2_params()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::SALT_LEN;

    #[test]
    fn default_params_validate() {
        KdfParams::default().validate().unwrap();
    }

    #[test]
    fn rejects_below_floor() {
        assert_eq!(
            KdfParams::new(MIN_M_COST - 1, DEFAULT_T_COST, DEFAULT_P_COST).validate(),
            Err(Error::InvalidKdfParameters)
        );
        assert_eq!(
            KdfParams::new(DEFAULT_M_COST, MIN_T_COST - 1, DEFAULT_P_COST).validate(),
            Err(Error::InvalidKdfParameters)
        );
    }

    #[test]
    fn rejects_above_ceiling() {
        assert_eq!(
            KdfParams::new(MAX_M_COST + 1, DEFAULT_T_COST, DEFAULT_P_COST).validate(),
            Err(Error::InvalidKdfParameters)
        );
    }

    #[test]
    fn rejects_degenerate_memory_parallelism() {
        assert_eq!(
            KdfParams::new(1, DEFAULT_T_COST, DEFAULT_P_COST).validate(),
            Err(Error::InvalidKdfParameters)
        );
    }

    #[test]
    fn derive_key_deterministic() {
        let params = KdfParams::default();
        let salt = [0x42u8; SALT_LEN];
        let k1 = derive_key(b"correct horse battery staple", &salt, &params).unwrap();
        let k2 = derive_key(b"correct horse battery staple", &salt, &params).unwrap();
        assert_eq!(&*k1, &*k2);
    }

    #[test]
    fn derive_key_changes_with_password() {
        let params = KdfParams::default();
        let salt = [0x42u8; SALT_LEN];
        let k1 = derive_key(b"password one", &salt, &params).unwrap();
        let k2 = derive_key(b"password two", &salt, &params).unwrap();
        assert_ne!(&*k1, &*k2);
    }

    #[test]
    fn derive_key_changes_with_salt() {
        let params = KdfParams::default();
        let s1 = [0x01u8; SALT_LEN];
        let s2 = [0x02u8; SALT_LEN];
        let k1 = derive_key(b"same password", &s1, &params).unwrap();
        let k2 = derive_key(b"same password", &s2, &params).unwrap();
        assert_ne!(&*k1, &*k2);
    }

    #[test]
    fn derive_key_requires_adequate_salt() {
        let params = KdfParams::default();
        assert_eq!(
            derive_key(b"pw", &[], &params),
            Err(Error::InvalidKdfParameters)
        );
        assert_eq!(
            derive_key(b"pw", &[0u8; 4], &params),
            Err(Error::InvalidKdfParameters)
        );
    }
}
