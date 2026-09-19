use passman::{crypto, security, Result};

fn main() {
    security::harden_process();
    if let Err(e) = demo() {
        eprintln!("passman: {e}");
        std::process::exit(1);
    }
}

fn demo() -> Result<()> {
    println!("passman encrypt/decrypt demo");
    let dek = crypto::keys::generate_dek()?;
    let nonce = crypto::random::random_nonce()?;
    let aad = b"passman-format-v1";
    let msg = b"secret payload";
    let ct = crypto::aead::encrypt(dek.as_ref(), &nonce, aad, msg)?;
    let pt = crypto::aead::decrypt(dek.as_ref(), &nonce, aad, &ct)?;
    if &pt[..] != msg {
        return Err(passman::Error::Authentication);
    }
    println!("decrypt OK, {} bytes plaintext", pt.len());
    Ok(())
}
