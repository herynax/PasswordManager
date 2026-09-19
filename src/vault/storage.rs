use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::crypto::random::random_array;
use crate::errors::{Error, Result};

use super::format::MAX_PAYLOAD_LEN;

const MAX_VAULT_FILE_LEN: u64 = MAX_PAYLOAD_LEN + 128 * 1024;

pub fn read_vault(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::InvalidFormat("vault path is not a regular file"));
    }
    if meta.len() > MAX_VAULT_FILE_LEN {
        return Err(Error::InvalidFormat("vault file too large"));
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::InsecurePermissions);
    }
    use std::os::unix::fs::MetadataExt;
    let uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    if uid != euid {
        return Err(Error::InsecurePermissions);
    }

    let mut bytes = Vec::with_capacity(meta.len() as usize);
    let mut handle = file;
    handle.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn write_vault(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(Error::InvalidFormat("vault directory does not exist"));
    }

    let mut tmp_path = tmp_name(path);
    let mut attempts = 0;
    let file = loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                attempts += 1;
                if attempts >= 8 {
                    return Err(Error::Io);
                }
                tmp_path = tmp_name(path);
            }
            Err(_) => return Err(Error::Io),
        }
    };

    let result = (|| -> Result<()> {
        let mut handle = file;
        handle.write_all(bytes)?;
        handle.flush()?;
        handle.sync_all()?;
        drop(handle);
        fs::rename(&tmp_path, path)?;
        sync_dir(parent)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

fn tmp_name(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_string());
    let rand: [u8; 8] = random_array().unwrap_or([0xAA; 8]);
    let hex: String = rand.iter().map(|b| format!("{b:02x}")).collect();
    path.with_file_name(format!(".{name}.tmp.{hex}"))
}

fn sync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_then_read() {
        let dir = std::env::temp_dir().join(format!("passman-storage-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.enc");
        let payload = b"encrypted-vault-bytes".repeat(3);

        write_vault(&path, &payload).unwrap();
        let loaded = read_vault(&path).unwrap();
        assert_eq!(loaded, payload);

        // No leftover temp files.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overwrite_is_atomic() {
        let dir = std::env::temp_dir().join(format!("passman-storage2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.enc");

        write_vault(&path, b"first version").unwrap();
        write_vault(&path, b"second version").unwrap();
        let loaded = read_vault(&path).unwrap();
        assert_eq!(loaded, b"second version");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_insecure_permissions() {
        let dir = std::env::temp_dir().join(format!("passman-storage3-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.enc");
        fs::write(&path, b"data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_vault(&path);
        assert_eq!(err, Err(Error::InsecurePermissions));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_gives_io_error() {
        let dir = std::env::temp_dir().join(format!("passman-storage4-{}", std::process::id()));
        let path = dir.join("nope.enc");
        assert_eq!(read_vault(&path), Err(Error::Io));
    }
}
