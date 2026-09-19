use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_passman")
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("passman-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(vault: &PathBuf, args: &[&str]) -> (i32, String, String) {
    let pass = "correct horse battery staple";
    let output = Command::new(bin())
        .args(args)
        .arg("--path")
        .arg(vault)
        .env("PASSMAN_PASSPHRASE", pass)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn run_with_stdin(vault: &PathBuf, args: &[&str], input: &str) -> (i32, String, String) {
    use std::io::Write;
    use std::process::{Child, Stdio};
    let pass = "correct horse battery staple";
    let mut child: Child = Command::new(bin())
        .args(args)
        .arg("--path")
        .arg(vault)
        .env("PASSMAN_PASSPHRASE", pass)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn full_cli_flow() {
    let dir = tmp_dir("flow");
    let vault = dir.join("vault.enc");

    // init
    let (code, out, err) = run(
        &vault,
        &["init", "--passphrase", "correct horse battery staple"],
    );
    assert_eq!(code, 0, "init stderr: {err}");
    assert!(out.contains("vault created"));
    assert!(vault.exists());

    // status (no unlock needed)
    let (code, out, _) = run(&vault, &["status"]);
    assert_eq!(code, 0);
    assert!(out.contains("passphrase slot: true"));

    // add login
    let (code, out, err) = run(
        &vault,
        &[
            "add",
            "--title",
            "GitHub",
            "--type",
            "login",
            "--username",
            "octocat",
            "--password",
            "s3cret!",
            "--url",
            "https://github.com",
            "--tags",
            "dev,work",
        ],
    );
    assert_eq!(code, 0, "add stderr: {err}");
    assert!(out.contains("saved login"));

    // add note
    let (code, out, err) = run(
        &vault,
        &[
            "add",
            "--title",
            "Grocery",
            "--type",
            "note",
            "--body",
            "eggs, milk, bread",
            "--tags",
            "home",
        ],
    );
    assert_eq!(code, 0, "add note stderr: {err}");
    assert!(out.contains("saved note"));

    // list
    let (code, out, _) = run(&vault, &["list"]);
    assert_eq!(code, 0);
    assert!(out.contains("GitHub"));
    assert!(out.contains("Grocery"));

    // get by title
    let (code, out, err) = run(&vault, &["get", "GitHub", "--reveal", "--no-copy"]);
    assert_eq!(code, 0, "get stderr: {err}");
    assert!(out.contains("octocat"));
    assert!(out.contains("s3cret!"));

    // get with clipboard disabled via --no-copy
    let (code, _, _) = run(&vault, &["get", "GitHub", "--no-copy"]);
    assert_eq!(code, 0);

    // search
    let (code, out, _) = run(&vault, &["search", "work"]);
    assert_eq!(code, 0);
    assert!(out.contains("GitHub"));

    // update password
    let (code, out, err) = run(&vault, &["update", "GitHub", "--password", "newpass!x"]);
    assert_eq!(code, 0, "update stderr: {err}");
    assert!(out.contains("updated"));
    let (_, out, _) = run(&vault, &["get", "GitHub", "--reveal", "--no-copy"]);
    assert!(out.contains("newpass!x"));

    // rm
    let (code, out, err) = run(&vault, &["rm", "Grocery"]);
    assert_eq!(code, 0, "rm stderr: {err}");
    assert!(out.contains("deleted"));
    let (_, out, _) = run(&vault, &["list"]);
    assert!(!out.contains("Grocery"));

    // change passphrase
    let (code, out, err) = run(
        &vault,
        &["pass", "--passphrase", "a new longer master password"],
    );
    assert_eq!(code, 0, "pass stderr: {err}");
    assert!(out.contains("changed"));

    // unlock with new passphrase still works
    let output = Command::new(bin())
        .args(["list", "--path"])
        .arg(&vault)
        .env("PASSMAN_PASSPHRASE", "a new longer master password")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("GitHub"));

    // wrong passphrase now rejected
    let output = Command::new(bin())
        .args(["list", "--path"])
        .arg(&vault)
        .env("PASSMAN_PASSPHRASE", "correct horse battery staple")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("authentication"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_help_is_available() {
    let output = Command::new(bin()).arg("--help").output().unwrap();
    assert_eq!(output.status.code().unwrap(), 0);
    let text = String::from_utf8_lossy(&output.stdout);
    for cmd in [
        "init", "status", "add", "get", "list", "search", "update", "rm", "generate", "pass",
    ] {
        assert!(text.contains(cmd), "help missing '{cmd}'");
    }
}

#[test]
fn generate_outputs_valid_password() {
    let output = Command::new(bin())
        .arg("generate")
        .arg("--length")
        .arg("24")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 0);
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.chars().count(), 24);
}

#[test]
fn backup_to_file_and_overwrite() {
    let dir = tmp_dir("backup");
    let vault = dir.join("vault.enc");
    let (code, _, err) = run(
        &vault,
        &["init", "--passphrase", "correct horse battery staple"],
    );
    assert_eq!(code, 0, "init stderr: {err}");

    // backup to an explicit file path
    let b1 = dir.join("backups").join("my-vault.enc");
    let (code, out, err) = run(&vault, &["backup", b1.to_str().unwrap()]);
    assert_eq!(code, 0, "backup stderr: {err}");
    assert!(out.contains("backup ok"));
    assert!(b1.exists());
    let first = std::fs::read(&b1).unwrap();
    assert_eq!(first, std::fs::read(&vault).unwrap());

    // add an entry -> vault changes
    let (code, _, err) = run(
        &vault,
        &[
            "add",
            "--title",
            "GitHub",
            "--username",
            "u",
            "--password",
            "pw",
            "--url",
            "https://g",
        ],
    );
    assert_eq!(code, 0, "add stderr: {err}");

    // re-backup overwrites the same file
    let (code, _, err) = run(&vault, &["backup", b1.to_str().unwrap()]);
    assert_eq!(code, 0, "re-backup stderr: {err}");
    let second = std::fs::read(&b1).unwrap();
    assert_ne!(first, second, "backup must reflect new vault");
    assert_eq!(second, std::fs::read(&vault).unwrap());
}

#[test]
fn backup_to_directory() {
    let dir = tmp_dir("backupdir");
    let vault = dir.join("vault.enc");
    let (code, _, err) = run(
        &vault,
        &["init", "--passphrase", "correct horse battery staple"],
    );
    assert_eq!(code, 0, "init stderr: {err}");

    let dest_dir = dir.join("stick");
    std::fs::create_dir_all(&dest_dir).unwrap();
    let trailing = format!("{}/", dest_dir.display());
    let (code, out, err) = run(&vault, &["backup", &trailing]);
    assert_eq!(code, 0, "dir backup stderr: {err}");
    assert!(out.contains("passman-vault-backup.enc"));

    let backup = dest_dir.join("passman-vault-backup.enc");
    assert!(backup.exists());
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        std::fs::read(&vault).unwrap()
    );
}

#[test]
fn backup_rejects_wrong_passphrase() {
    let dir = tmp_dir("backupw");
    let vault = dir.join("vault.enc");
    let (code, _, err) = run(
        &vault,
        &["init", "--passphrase", "correct horse battery staple"],
    );
    assert_eq!(code, 0, "init stderr: {err}");

    let output = Command::new(bin())
        .args(["backup"])
        .arg(dir.join("x.enc"))
        .arg("--path")
        .arg(&vault)
        .env("PASSMAN_PASSPHRASE", "wrong passphrase")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("authentication"));
    assert!(!dir.join("x.enc").exists());
}

#[test]
fn get_multiple_accounts_shows_menu_and_selects() {
    let dir = tmp_dir("menu");
    let vault = dir.join("vault.enc");
    let (code, _, err) = run(
        &vault,
        &["init", "--passphrase", "correct horse battery staple"],
    );
    assert_eq!(code, 0, "init stderr: {err}");

    for (u, pw) in [("acc1@gmail.com", "pw-acc1"), ("acc2@gmail.com", "pw-acc2")] {
        let (code, _, err) = run(
            &vault,
            &[
                "add",
                "--title",
                "Steam",
                "--username",
                u,
                "--password",
                pw,
                "--url",
                "https://steamcommunity.com",
            ],
        );
        assert_eq!(code, 0, "add stderr: {err}");
    }

    // ambiguous title -> menu lists both usernames
    let (code, out, err) = run(&vault, &["get", "Steam", "--no-copy"]);
    assert_eq!(code, 1, "no stdin -> ambiguous, stderr: {err}");
    assert!(out.contains("multiple matches"));
    assert!(out.contains("acc1@gmail.com"));
    assert!(out.contains("acc2@gmail.com"));
    assert!(err.contains("ambiguous"));

    // choose the 2nd via stdin
    let (code, out, err) = run_with_stdin(&vault, &["get", "Steam", "--no-copy"], "2\n");
    assert_eq!(code, 0, "select stderr: {err}");
    assert!(out.contains("acc2@gmail.com"));
    assert!(!out.contains("pw-acc2"), "password hidden without --reveal");

    // choose 1st
    let (code, out, err) = run_with_stdin(&vault, &["get", "Steam", "--no-copy"], "1\n");
    assert_eq!(code, 0, "select stderr: {err}");
    assert!(out.contains("acc1@gmail.com"));

    // 'q' aborts
    let (code, _, err) = run_with_stdin(&vault, &["get", "Steam", "--no-copy"], "q\n");
    assert_eq!(code, 1);
    assert!(err.contains("aborted"));

    let _ = std::fs::remove_dir_all(&dir);
}
