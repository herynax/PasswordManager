use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> Secret<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self(Zeroizing::new(data))
    }
}

impl<const N: usize> std::convert::AsRef<[u8; N]> for Secret<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Secret<N> {
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{}>(<redacted>)", N)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new([0x41u8; 32]);
        let d = format!("{:?}", s);
        assert!(!d.contains("AAAA"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn zeroize_wipes() {
        let mut s = Secret::new([0x41u8; 32]);
        s.zeroize();
        assert_eq!(&*s.0, &[0u8; 32]);
    }
}
