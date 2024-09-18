mod base32;
mod connection;
mod crypt;
mod digest;
mod error;
mod key;
mod models;
mod vault_entry;

#[allow(unused_imports)]
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::HashMap;

use crate::error::CacheVaultError;
use crate::models::*;

pub async fn save(
    namespace: &str,
    key_name: &str,
    value: &str,
    attributes: Option<HashMap<String, String>>,
    expired_at: Option<NaiveDateTime>,
) -> Result<(), CacheVaultError> {
    let entry_id = Entry::upsert(namespace, key_name, value, expired_at).await?;
    if let Some(new_attributes) = attributes {
        for (name, value) in new_attributes.iter() {
            let _ = Attribute::upsert(entry_id, name, value).await?;
        }
    }
    Ok(())
}

pub async fn fetch(namespace: &str, key_name: &str) -> Result<(String, Option<NaiveDateTime>), CacheVaultError> {
    let entry = Entry::fetch(namespace, key_name).await?;
    Ok((entry.plaintext()?, entry.expired_at))
}

pub async fn fetch_with_attributes(
    namespace: &str,
    key_name: &str,
) -> Result<(String, Option<NaiveDateTime>, Option<HashMap<String, String>>), CacheVaultError> {
    let entry = Entry::fetch(namespace, key_name).await?;
    let attributes = Attribute::fetch_all(entry.id)
        .await?
        .iter()
        .map(|a| Ok((a.name.to_string(), a.plaintext()?)))
        .collect::<Result<HashMap<String, String>, CacheVaultError>>()?;
    if attributes.is_empty() {
        Ok((entry.plaintext()?, entry.expired_at, None))
    } else {
        Ok((entry.plaintext()?, entry.expired_at, Some(attributes)))
    }
}

// fn async search_by_attributes(namespace: &str, attributes: HashMap<String, String>) -> Result<String, CacheVaultError> {
//    todo!()
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::migrate;

    #[tokio::test]
    async fn test_save() -> Result<(), CacheVaultError> {
        migrate().await?;
        save("test", "test-key1", "test-value1", None, None).await?;
        save("test", "test-key2", "test-value2", None, None).await?;
        let (value1, _) = fetch("test", "test-key1").await?;
        assert_eq!(value1, "test-value1");
        let (value2, _) = fetch("test", "test-key2").await?;
        assert_eq!(value2, "test-value2");

        let (value1, _, attributes) = fetch_with_attributes("test", "test-key1").await?;
        assert_eq!(value1, "test-value1");
        assert_eq!(attributes, None);

        match fetch("test", "no-such-key").await {
            Err(e) => match e {
                CacheVaultError::SqlxError(sqlx::Error::RowNotFound) => (),
                _ => panic!("unexpected"),
            },
            Ok(_) => panic!("unexpected"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_save_with_attributes() -> Result<(), CacheVaultError> {
        migrate().await?;
        let attributes = HashMap::from([
            (String::from("attr1"), String::from("attr1-value")),
            (String::from("attr2"), String::from("attr2-value")),
            (String::from("attr3"), String::from("attr3-value")),
        ]);
        save("test", "test-key1", "test-value1", Some(attributes.clone()), None).await?;

        if let (value1, _, Some(attrs)) = fetch_with_attributes("test", "test-key1").await? {
            assert_eq!(value1, "test-value1");
            assert_eq!(attrs, attributes);
        } else {
            panic!("unexpected");
        }

        Ok(())
    }
}
