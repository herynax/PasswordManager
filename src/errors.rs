#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("authentication failed: wrong master secret or corrupted vault")]
    Authentication,

    #[error("invalid KDF parameters")]
    InvalidKdfParameters,

    #[error("unsupported vault format version {0}.{1}")]
    UnsupportedVersion(u8, u8),

    #[error("cryptographic operation failed")]
    Crypto,

    #[error("random number generation failed")]
    Rng,

    #[error("invalid vault format: {0}")]
    InvalidFormat(&'static str),

    #[error("unsupported KDF identifier {0}")]
    UnsupportedKdf(u8),

    #[error("unsupported cipher identifier {0}")]
    UnsupportedCipher(u8),

    #[error("no usable key slot for the provided secret")]
    NoUsableSlot,

    #[error("insecure file permissions (vault must be 0600, owned by the user)")]
    InsecurePermissions,

    #[error("I/O error")]
    Io,
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Io
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<argon2::Error> for Error {
    fn from(_: argon2::Error) -> Self {
        Error::Crypto
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Error::Authentication
    }
}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Error::Rng
    }
}
