use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::clipboard::{self, backend_from_env};
use crate::errors::{Error, Result};
use crate::generator::{self, GenOptions};
use crate::vault::payload::{self, now_unix, Entry, EntryBody, EntryType, LoginData, NoteData};
use crate::vault::{storage, Unlocked, VaultFile};

const CACHE_DIR: &str = "passman";

fn default_vault_path() -> PathBuf {
    if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg_data).join(CACHE_DIR).join("vault.enc");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(CACHE_DIR)
            .join("vault.enc");
    }
    PathBuf::from("vault.enc")
}

#[derive(Parser, Debug)]
#[command(
    name = "passman",
    version,
    about = "Local, offline-first encrypted password manager for Linux",
    long_about = "passman — локальный офлайн password manager.

Данные хранятся в зашифрованном vault-файле (XChaCha20-Poly1305, ключ от
Argon2id). Ключ не хранится на диске: он выводится из мастер-пароля на время
выполнения каждой команды, и сразу уничтожается (stateless).

Все команды, работающие с содержимым, запрашивают мастер-пароль из терминала
(без эха). Ввод пароля в clipboard автоматически очищается через ~15 секунд."
)]
struct Cli {
    /// Vault file path (default: $XDG_DATA_HOME/passman/vault.enc)
    #[arg(short, long, global = true, value_name = "FILE")]
    path: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new (empty) vault
    Init {
        /// Master passphrase (skips the secure prompt; for scripts)
        #[arg(long, hide = true)]
        passphrase: Option<String>,
    },

    /// Show vault metadata without unlocking
    Status,

    /// Add a new entry (interactive)
    Add {
        /// Entry title (required)
        #[arg(long)]
        title: String,
        /// Entry type: login | note
        #[arg(long, default_value = "login")]
        r#type: String,
        /// Username (login)
        #[arg(long)]
        username: Option<String>,
        /// Password (login); prompts if omitted
        #[arg(long)]
        password: Option<String>,
        /// URL (login)
        #[arg(long)]
        url: Option<String>,
        /// Body text (note); prompts (multi-line) if omitted
        #[arg(long)]
        body: Option<String>,
        /// Comma-separated tags
        #[arg(long)]
        tags: Option<String>,
    },

    /// Show one entry (password auto-copied to clipboard)
    Get {
        /// Entry id, id-prefix, or (part of) title
        target: String,
        /// Print the password in the terminal instead of copying
        #[arg(long)]
        reveal: bool,
        /// Do not copy the password to the clipboard
        #[arg(long)]
        no_copy: bool,
    },

    /// List entries (id, type, title, tags)
    List,

    /// Search entries by title or tags
    Search { query: String },

    /// Update entry fields (id or title)
    Update {
        target: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        tags: Option<String>,
    },

    /// Delete an entry (id or title)
    Rm { target: String },

    /// Generate a random password
    Generate {
        /// Password length
        #[arg(long, default_value_t = generator::DEFAULT_LENGTH)]
        length: usize,
        /// Exclude symbols
        #[arg(long)]
        no_symbols: bool,
        /// Include ambiguous characters (0O1lI|...)
        #[arg(long)]
        ambiguous: bool,
        /// Copy to clipboard (auto-clear)
        #[arg(long)]
        copy: bool,
    },

    /// Change the master passphrase
    Pass {
        /// New passphrase (skips the secure prompt; for scripts)
        #[arg(long, hide = true)]
        passphrase: Option<String>,
    },

    /// Back up the vault to a directory or a file path
    Backup {
        /// Destination directory (needs trailing `/`) or file path; existing
        /// file is overwritten
        destination: PathBuf,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.path.unwrap_or_else(default_vault_path);
    match cli.command {
        Command::Init { passphrase } => cmd_init(&path, passphrase),
        Command::Status => cmd_status(&path),
        Command::Add {
            title,
            r#type,
            username,
            password,
            url,
            body,
            tags,
        } => cmd_add(AddArgs {
            path: &path,
            title: &title,
            r#type: &r#type,
            username,
            password,
            url,
            body,
            tags,
        }),
        Command::Get {
            target,
            reveal,
            no_copy,
        } => cmd_get(&path, &target, reveal, no_copy),
        Command::List => cmd_list(&path),
        Command::Search { query } => cmd_search(&path, &query),
        Command::Update {
            target,
            title,
            username,
            password,
            url,
            body,
            tags,
        } => cmd_update(UpdateArgs {
            path: &path,
            target: &target,
            title,
            username,
            password,
            url,
            body,
            tags,
        }),
        Command::Rm { target } => cmd_rm(&path, &target),
        Command::Generate {
            length,
            no_symbols,
            ambiguous,
            copy,
        } => cmd_generate(length, no_symbols, ambiguous, copy),
        Command::Pass { passphrase } => cmd_pass(&path, passphrase),
        Command::Backup { destination } => cmd_backup(&path, &destination),
    }
}

fn prompt_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    // Supply via PASSMAN_PASSPHRASE for scripts/tests; otherwise prompt on tty.
    if let Ok(v) = std::env::var("PASSMAN_PASSPHRASE") {
        let v = Zeroizing::new(v);
        if v.is_empty() {
            return Err(Error::InvalidFormat("PASSMAN_PASSPHRASE is empty"));
        }
        return Ok(v);
    }
    let value = rpassword::prompt_password(prompt)?;
    Ok(Zeroizing::new(value))
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn unlock(path: &Path, label: &str) -> Result<Unlocked> {
    let file = VaultFile::open(path)?;
    let passphrase = prompt_passphrase(&format!("Master password ({label}): "))?;
    file.unlock(passphrase.as_bytes())
}

fn save(path: &Path, unlocked: &Unlocked) -> Result<()> {
    let bytes = unlocked.serialize()?;
    storage::write_vault(path, &bytes)
}

fn decode_type(s: &str) -> Result<EntryType> {
    match s.to_lowercase().as_str() {
        "login" | "log" => Ok(EntryType::Login),
        "note" | "n" => Ok(EntryType::Note),
        _ => Err(Error::InvalidFormat("unknown entry type (login|note)")),
    }
}

fn parse_tags(s: Option<String>) -> Vec<String> {
    s.map(|v| {
        v.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn cmd_init(path: &Path, passphrase: Option<String>) -> Result<()> {
    if std::fs::metadata(path).is_ok() {
        return Err(Error::InvalidFormat("vault already exists at this path"));
    }
    let pass = match passphrase {
        Some(p) if !p.is_empty() => Zeroizing::new(p),
        _ => {
            let p1 = prompt_passphrase("New master password: ")?;
            if p1.len() < 8 {
                return Err(Error::InvalidFormat(
                    "master password must be at least 8 characters",
                ));
            }
            let p2 = prompt_passphrase("Confirm master password: ")?;
            if *p1 != *p2 {
                return Err(Error::InvalidFormat("passwords do not match"));
            }
            p1
        }
    };
    ensure_parent_dir(path)?;
    let unlocked = Unlocked::create(pass.as_bytes(), &crate::crypto::kdf::KdfParams::default())?;
    save(path, &unlocked)?;
    println!("vault created: {}", path.display());
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn cmd_status(path: &Path) -> Result<()> {
    let file = VaultFile::open(path)?;
    println!("path:       {}", path.display());
    println!(
        "vault id:   {}",
        file.vault_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("key slots:  {}", file.slot_count());
    println!("passphrase slot: {}", file.has_passphrase_slot());
    Ok(())
}

struct AddArgs<'a> {
    path: &'a Path,
    title: &'a str,
    r#type: &'a str,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    body: Option<String>,
    tags: Option<String>,
}

fn cmd_add(args: AddArgs) -> Result<()> {
    let AddArgs {
        path,
        title,
        r#type,
        username,
        password,
        url,
        body,
        tags,
    } = args;
    if title.trim().is_empty() {
        return Err(Error::InvalidFormat("title is required"));
    }
    let kind = decode_type(r#type)?;

    if kind == EntryType::Note {
        let body = match body {
            Some(b) => b,
            None => prompt_line("Body (end with Ctrl-D, blank line to stop): ")?,
        };
        let mut unlocked = unlock(path, title)?;
        let entry = Entry {
            id: payload::generate_id()?,
            title: title.to_string(),
            tags: parse_tags(tags),
            created_at: now_unix(),
            updated_at: now_unix(),
            body: EntryBody::Note(NoteData { body }),
        };
        unlocked.add_entry(entry)?;
        save(path, &unlocked)?;
        println!("saved note '{title}'");
        return Ok(());
    }

    // Login
    let username = match username {
        Some(u) => u,
        None => prompt_line("Username: ")?,
    };
    let password = match password {
        Some(p) if !p.is_empty() => Zeroizing::new(p),
        _ => {
            let p1 = prompt_passphrase("Password: ")?;
            let p2 = prompt_passphrase("Confirm password: ")?;
            if *p1 != *p2 {
                return Err(Error::InvalidFormat("passwords do not match"));
            }
            p1
        }
    };
    let url = match url {
        Some(u) => u,
        None => prompt_line("URL (optional): ")?,
    };

    let mut unlocked = unlock(path, title)?;
    let entry = Entry {
        id: payload::generate_id()?,
        title: title.to_string(),
        tags: parse_tags(tags),
        created_at: now_unix(),
        updated_at: now_unix(),
        body: EntryBody::Login(LoginData {
            username,
            password: (*password).clone(),
            url,
        }),
    };
    unlocked.add_entry(entry)?;
    save(path, &unlocked)?;
    println!("saved login '{title}'");
    Ok(())
}

fn resolve_id(unlocked: &Unlocked, target: &str) -> Result<String> {
    let exact: Vec<&Entry> = unlocked
        .entries()
        .iter()
        .filter(|e| e.id == target)
        .collect();
    let prefix: Vec<&Entry> = unlocked
        .entries()
        .iter()
        .filter(|e| e.id.starts_with(target) && e.id != target)
        .collect();
    let by_title: Vec<&Entry> = unlocked
        .entries()
        .iter()
        .filter(|e| e.id != target && title_contains(e, target))
        .collect();

    let matches: Vec<&Entry> = if !exact.is_empty() {
        exact
    } else if !prefix.is_empty() {
        prefix
    } else {
        by_title
    };

    match matches.len() {
        0 => Err(Error::InvalidFormat("no matching entry")),
        1 => Ok(matches[0].id.clone()),
        _ => choose_entry(&matches),
    }
}

fn entry_label(entry: &Entry) -> String {
    match &entry.body {
        EntryBody::Login(l) => {
            if l.username.is_empty() {
                "(no username)".to_string()
            } else {
                l.username.clone()
            }
        }
        EntryBody::Note(n) => truncate(n.body.trim(), 40).to_string(),
    }
}

fn choose_entry(matches: &[&Entry]) -> Result<String> {
    println!("multiple matches:");
    for (i, entry) in matches.iter().enumerate() {
        println!("  {}. {}  | {}", i + 1, entry.title, entry_label(entry));
    }
    let line = prompt_line("Choose an account by number (or q to abort): ")?;
    match line.trim() {
        "q" | "Q" => Err(Error::InvalidFormat("aborted by user")),
        s => match s.parse::<usize>() {
            Ok(n) if n >= 1 && n <= matches.len() => Ok(matches[n - 1].id.clone()),
            _ => {
                let ids: Vec<&str> = matches.iter().map(|e| e.id.as_str()).collect();
                Err(Error::Ambiguous(ids.join(", ")))
            }
        },
    }
}

fn title_contains(entry: &Entry, needle: &str) -> bool {
    entry.title.to_lowercase().contains(&needle.to_lowercase())
}

fn cmd_get(path: &Path, target: &str, reveal: bool, no_copy: bool) -> Result<()> {
    let unlocked = unlock(path, target)?;
    let id = resolve_id(&unlocked, target)?;
    let entry = unlocked.get_entry(&id).unwrap();

    println!("title:      {}", entry.title);
    match &entry.body {
        EntryBody::Login(l) => {
            print_type(EntryType::Login);
            println!("username:   {}", l.username);
            println!("url:        {}", l.url);
            if !entry.tags.is_empty() {
                println!("tags:       {}", entry.tags.join(", "));
            }
            if reveal {
                println!("password:   {}", l.password);
            } else if no_copy {
                // nothing
            } else {
                clipboard::copy_to_clipboard(&l.password)?;
                clipboard::schedule_clear(backend_from_env())?;
                println!("password:   (copied to clipboard, auto-clears in ~15s)");
            }
        }
        EntryBody::Note(n) => {
            print_type(EntryType::Note);
            if !entry.tags.is_empty() {
                println!("tags:       {}", entry.tags.join(", "));
            }
            println!("--- body ---");
            println!("{}", n.body);
        }
    }
    println!("id:         {}", entry.id);
    println!("updated:    {}", entry.updated_at);
    Ok(())
}

fn print_type(kind: EntryType) {
    println!("type:       {}", kind.label());
}

fn cmd_list(path: &Path) -> Result<()> {
    let unlocked = unlock(path, "list")?;
    let entries = unlocked.entries();
    if entries.is_empty() {
        println!("(empty vault)");
        return Ok(());
    }
    println!("ID              TYPE   TITLE                    TAGS");
    for e in entries {
        let kind = match &e.body {
            EntryBody::Login(_) => "login",
            EntryBody::Note(_) => "note",
        };
        println!(
            "{:16} {:<6} {:<24} {}",
            short_id(&e.id),
            kind,
            truncate(&e.title, 24),
            e.tags.join(",")
        );
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

fn cmd_search(path: &Path, query: &str) -> Result<()> {
    let unlocked = unlock(path, "search")?;
    let results = unlocked.search(query);
    if results.is_empty() {
        println!("(no matches)");
        return Ok(());
    }
    println!("ID              TYPE   TITLE                    TAGS");
    for e in results {
        let kind = match &e.body {
            EntryBody::Login(_) => "login",
            EntryBody::Note(_) => "note",
        };
        println!(
            "{:16} {:<6} {:<24} {}",
            short_id(&e.id),
            kind,
            truncate(&e.title, 24),
            e.tags.join(",")
        );
    }
    Ok(())
}

struct UpdateArgs<'a> {
    path: &'a Path,
    target: &'a str,
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    body: Option<String>,
    tags: Option<String>,
}

fn cmd_update(args: UpdateArgs) -> Result<()> {
    let UpdateArgs {
        path,
        target,
        title,
        username,
        password,
        url,
        body,
        tags,
    } = args;
    let mut unlocked = unlock(path, "update")?;
    let id = resolve_id(&unlocked, target)?;
    unlocked.update_entry(&id, |entry| {
        if let Some(t) = title {
            entry.title = t;
        }
        match (&mut entry.body, &username, &password, &url, &body) {
            (EntryBody::Login(l), Some(u), _, _, _) => l.username = u.clone(),
            (EntryBody::Login(l), None, Some(p), _, _) => l.password = p.clone(),
            (EntryBody::Login(l), _, _, Some(u), _) => l.url = u.clone(),
            (EntryBody::Note(n), _, _, _, Some(b)) => n.body = b.clone(),
            _ => {}
        }
        if let Some(t) = tags {
            entry.tags = parse_tags(Some(t));
        }
    })?;
    save(path, &unlocked)?;
    println!("updated '{id}'");
    Ok(())
}

fn cmd_rm(path: &Path, target: &str) -> Result<()> {
    let mut unlocked = unlock(path, "delete")?;
    let id = resolve_id(&unlocked, target)?;
    if unlocked.delete_entry(&id) {
        save(path, &unlocked)?;
        println!("deleted '{id}'");
    } else {
        println!("(nothing deleted)");
    }
    Ok(())
}

fn cmd_generate(length: usize, no_symbols: bool, ambiguous: bool, copy: bool) -> Result<()> {
    let options = GenOptions {
        length,
        symbols: !no_symbols,
        exclude_ambiguous: !ambiguous,
        ..Default::default()
    };
    let password = generator::generate(&options)?;
    if copy {
        clipboard::copy_to_clipboard(&password)?;
        clipboard::schedule_clear(backend_from_env())?;
        println!("password: (copied to clipboard, auto-clears in ~15s)");
    } else {
        println!("{}", *password);
    }
    Ok(())
}

fn cmd_pass(path: &Path, passphrase: Option<String>) -> Result<()> {
    let mut unlocked = unlock(path, "change passphrase")?;
    let new_pass = match passphrase {
        Some(p) if !p.is_empty() => Zeroizing::new(p),
        _ => {
            let p1 = prompt_passphrase("New master password: ")?;
            if p1.len() < 8 {
                return Err(Error::InvalidFormat(
                    "master password must be at least 8 characters",
                ));
            }
            let p2 = prompt_passphrase("Confirm new master password: ")?;
            if *p1 != *p2 {
                return Err(Error::InvalidFormat("passwords do not match"));
            }
            p1
        }
    };
    unlocked.change_passphrase(new_pass.as_bytes())?;
    save(path, &unlocked)?;
    println!("master passphrase changed");
    Ok(())
}

const BACKUP_FILENAME: &str = "passman-vault-backup.enc";

fn resolve_backup_target(destination: &Path) -> PathBuf {
    let is_dir = destination.is_dir()
        || destination
            .to_string_lossy()
            .ends_with(std::path::MAIN_SEPARATOR);
    if is_dir {
        destination.join(BACKUP_FILENAME)
    } else {
        destination.to_path_buf()
    }
}

fn cmd_backup(path: &Path, destination: &Path) -> Result<()> {
    unlock(path, "backup")?;

    let bytes = storage::read_vault(path)?;
    let dst = resolve_backup_target(destination);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    storage::write_vault(&dst, &bytes)?;

    let written = std::fs::read(&dst)?;
    if written != bytes {
        return Err(Error::InvalidFormat(
            "backup verification failed: bytes differ",
        ));
    }
    println!("backup ok: {} bytes -> {}", bytes.len(), dst.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_entry_types() {
        assert_eq!(decode_type("login").unwrap(), EntryType::Login);
        assert_eq!(decode_type("NOTE").unwrap(), EntryType::Note);
        assert!(decode_type("bank").is_err());
    }

    #[test]
    fn parse_tags_splits_and_trims() {
        assert_eq!(parse_tags(Some(" a, b , ,c ".into())), vec!["a", "b", "c"]);
        assert!(parse_tags(None).is_empty());
    }

    #[test]
    fn truncate_ellipsis() {
        assert_eq!(truncate("short", 24), "short");
        assert_eq!(truncate("abcdefghij", 8), "abcde...");
    }
}
