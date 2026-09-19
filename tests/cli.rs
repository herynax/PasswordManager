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
