use argon2::Argon2;

use crate::error::CacheVaultError;
use crate::key::Key;

pub fn digest(data: &[u8]) -> Result<[u8; 32], CacheVaultError> {
    let pepper = Key::pepper().get()?;
    let mut output = [0u8; 32];
    let _ = Argon2::default().hash_password_into(data, &pepper, &mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest() -> Result<(), CacheVaultError> {
        let v1 = digest(b"secret-password")?;
        let v2 = digest(b"secret-password")?;
        let v3 = digest(b"secret-password2")?;

        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
        Ok(())
    }
}
