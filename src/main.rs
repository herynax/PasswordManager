use passman::{cli, security};

fn main() {
    security::harden_process();
    match cli::run() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("passman: {e}");
            std::process::exit(1);
        }
    }
}
