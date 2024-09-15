#[allow(unused_imports)]
use chacha20poly1305::aead::{KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use keyring::Entry;

use crate::base32::{decode, encode};
use crate::error::CacheVaultError;

#[derive(Debug)]
pub struct Key {
    service: &'static str,
    user: &'static str,
}

fn generate_key() -> String {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng).to_vec();
    encode(&key)
}

impl Key {
    #[allow(dead_code)]
    pub fn new(service: &'static str, user: &'static str) -> Self {
        Self { service, user }
    }

    pub fn default() -> Self {
        Self {
            service: "cache-vault",
            user: "encryption-key",
        }
    }

    pub fn pepper() -> Self {
        Self {
            service: "cache-vault",
            user: "pepper",
        }
    }

    pub fn get(&self) -> Result<Vec<u8>, CacheVaultError> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(key_str) => decode(key_str.as_str()).ok_or(CacheVaultError::Decode),
            Err(e) => match e {
                keyring::Error::NoEntry => {
                    entry
                        .set_password(generate_key().as_str())
                        .map_err(CacheVaultError::Keyring)?;
                    self.get()
                }
                e => Err(CacheVaultError::Keyring(e)),
            },
        }
    }

    #[allow(dead_code)]
    pub fn delete(&self) -> Result<(), CacheVaultError> {
        let entry = self.entry()?;
        entry.delete_password().map_err(CacheVaultError::Keyring)
    }

    fn entry(&self) -> Result<keyring::Entry, CacheVaultError> {
        Entry::new(self.service, self.user).map_err(CacheVaultError::Keyring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let k = generate_key();
        println!("{}", k);
    }

    #[test]
    fn test_key_new_and_get() {
        let k = Key::new("cache-vault-test", "cache-vault-test-user");
        let pw = k.get();
        println!("{:?}", pw);
        k.delete().unwrap();
    }
}
