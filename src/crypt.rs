use crate::error::CacheVaultError;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::key::Key;

pub fn encrypt(raw: String) -> Result<(Vec<u8>, Vec<u8>), CacheVaultError> {
    let key = Key::default().get()?;
    let key = GenericArray::from_slice(&key);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let plaintext = Payload::from(raw.as_bytes());
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(CacheVaultError::ChaCha20)?;
    Ok((ciphertext, nonce.to_vec()))
}

pub fn decrypt(nonce: &Vec<u8>, encrypted: &Vec<u8>) -> Result<String, CacheVaultError> {
    let key = Key::default().get()?;
    let key = GenericArray::from_slice(&key);
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = Payload::from(encrypted.as_ref());
    let nonce = GenericArray::from_slice(nonce.as_ref());
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(CacheVaultError::ChaCha20)?;
    String::from_utf8(plaintext).map_err(CacheVaultError::FromUtf8Error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let plaintext = String::from("Hello, Rust");
        let (encrypted, nonce) = encrypt(plaintext.clone()).context("encrypt error")?;
        let decrypted = decrypt(&nonce, &encrypted).context("decrypt error")?;
        assert_eq!(plaintext, decrypted);
        Ok(())
    }
}
