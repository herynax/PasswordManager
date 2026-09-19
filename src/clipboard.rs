use std::process::{Command, Stdio};

use crate::errors::{Error, Result};

const CLEAR_DELAY_DEFAULT: u64 = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardBackend {
    WlCopy,
    Xclip,
}

fn detect_backend() -> Result<ClipboardBackend> {
    if Command::new("wl-copy")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(ClipboardBackend::WlCopy);
    }
    if Command::new("xclip")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(ClipboardBackend::Xclip);
    }
    Err(Error::InvalidFormat(
        "neither wl-copy nor xclip found; install wl-clipboard or xclip",
    ))
}

pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let backend = detect_backend()?;
    let mut cmd = match backend {
        ClipboardBackend::WlCopy => {
            let mut c = Command::new("wl-copy");
            c.stdin(Stdio::piped());
            c
        }
        ClipboardBackend::Xclip => {
            let mut c = Command::new("xclip");
            c.arg("-selection").arg("clipboard").stdin(Stdio::piped());
            c
        }
    };
    let mut child = cmd.spawn()?;
    {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())?;
        }
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Crypto)
    }
}

pub fn schedule_clear(backend: Option<ClipboardBackend>) -> Result<()> {
    let backend = match backend {
        Some(b) => b,
        None => detect_backend()?,
    };
    let cmd_line = match backend {
        ClipboardBackend::WlCopy => "sleep {delay}; wl-copy --clear".to_string(),
        ClipboardBackend::Xclip => {
            "sleep {delay}; echo -n | xclip -selection clipboard".to_string()
        }
    }
    .replace("{delay}", &CLEAR_DELAY_DEFAULT.to_string());

    // Detach so the caller's process can exit immediately; the background
    // subshell survives to run the clear after the delay.
    let child = Command::new("sh")
        .arg("-c")
        .arg(&cmd_line)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Intentionally keep the child handle to prevent reaping zombies while
    // not blocking the caller.
    std::mem::forget(child);
    Ok(())
}

pub fn backend_from_env() -> Option<ClipboardBackend> {
    match std::env::var("WAYLAND_DISPLAY") {
        Ok(_) => Some(ClipboardBackend::WlCopy),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_schedule_delay_uses_default() {
        assert_eq!(CLEAR_DELAY_DEFAULT, 15);
    }
}
