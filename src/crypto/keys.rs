use crate::crypto::random::random_array;
use crate::errors::Result;
use zeroize::Zeroizing;

pub fn generate_dek() -> Result<Zeroizing<[u8; 32]>> {
    let dek = random_array::<32>()?;
    Ok(Zeroizing::new(dek))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dek_is_32_random_bytes() {
        let d1 = generate_dek().unwrap();
        let d2 = generate_dek().unwrap();
        assert_eq!(d1.len(), 32);
        assert_ne!(&*d1, &*d2);
    }
}
