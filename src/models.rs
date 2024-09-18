use anyhow::Context;
use chrono::NaiveDateTime;

use crate::connection::POOL;
use crate::crypt::{decrypt, encrypt};
use crate::digest::digest;
use crate::error::CacheVaultError;

#[derive(Debug, Eq, PartialEq)]
pub struct Entry {
    pub id: i64,
    pub namespace: String,
    pub key_name: String,
    pub nonce: Vec<u8>,
    pub encrypted_value: Vec<u8>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub expired_at: Option<NaiveDateTime>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Attribute {
    pub id: i64,
    pub entry_id: i64,
    pub name: String,
    pub nonce: Vec<u8>,
    pub encrypted_value: Vec<u8>,
    pub hashed_value: Vec<u8>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl Entry {
    pub fn plaintext(&self) -> Result<String, CacheVaultError> {
        decrypt(&self.nonce, &self.encrypted_value)
    }

    pub async fn fetch(namespace: &str, key_name: &str) -> Result<Self, CacheVaultError> {
        let entry = sqlx::query_as!(
            Entry,
            r#"
              select
                id
              , namespace
              , key_name
              , nonce
              , encrypted_value
              , created_at
              , updated_at
              , expired_at
              from
                entries
              where
               namespace = $1
               and
               key_name = $2
            "#,
            namespace,
            key_name
        )
        .fetch_one(&*POOL)
        .await?;
        Ok(entry)
    }

    #[allow(dead_code)]
    pub async fn fetch_by_id(id: i64) -> Result<Self, CacheVaultError> {
        let entry = sqlx::query_as!(
            Entry,
            r#"
              select
                id
              , namespace
              , key_name
              , nonce
              , encrypted_value
              , created_at
              , updated_at
              , expired_at
              from
                entries
              where
                id = $1
            "#,
            id
        )
        .fetch_one(&*POOL)
        .await?;
        Ok(entry)
    }

    // pub async fn search_by_attributes(namespace: &str, attributes: HashMap<String, String>) -> Result<Self, CacheVaultError> {
    //     todo!()
    // }

    pub async fn upsert(
        namespace: &str,
        key_name: &str,
        value: &str,
        expired_at: Option<NaiveDateTime>,
    ) -> Result<i64, CacheVaultError> {
        let (encrypted_value, nonce) = encrypt(value.to_string())?;
        let id = sqlx::query!(
            r#"
              insert into
                entries(namespace, key_name, nonce, encrypted_value, created_at, updated_at, expired_at)
                values ($1, $2, $3, $4, datetime('now'), datetime('now'), $5)
                on conflict (namespace, key_name) do update set
                  nonce = $3
                , encrypted_value = $4
                , updated_at = datetime('now')
                , expired_at = $5
            "#,
            namespace,
            key_name,
            nonce,
            encrypted_value,
            expired_at,
        )
        .execute(&*POOL)
        .await
        .with_context(|| {
            format!(
                "failed to upsert entries namespace={:?}, key_name={:?}",
                namespace, key_name
            )
        })?
        .last_insert_rowid();
        Ok(id)
    }
}

impl Attribute {
    pub fn plaintext(&self) -> Result<String, CacheVaultError> {
        decrypt(&self.nonce, &self.encrypted_value)
    }

    #[allow(dead_code)]
    pub async fn fetch_by_id(id: i64) -> Result<Self, CacheVaultError> {
        let attribute = sqlx::query_as!(
            Attribute,
            r#"
              select
                id
              , entry_id
              , name
              , nonce
              , encrypted_value
              , hashed_value
              , created_at
              , updated_at
              from
                attributes
              where
                id = $1
            "#,
            id
        )
        .fetch_one(&*POOL)
        .await?;
        Ok(attribute)
    }

    #[allow(dead_code)]
    pub async fn fetch_by_name(entry_id: i64, name: &str) -> Result<Self, CacheVaultError> {
        let attribute = sqlx::query_as!(
            Attribute,
            r#"
              select
                id
              , entry_id
              , name
              , nonce
              , encrypted_value
              , hashed_value
              , created_at
              , updated_at
              from
                attributes
              where
                entry_id = $1
                and
                name = $2
            "#,
            entry_id,
            name
        )
        .fetch_one(&*POOL)
        .await?;
        Ok(attribute)
    }

    pub async fn fetch_all(entry_id: i64) -> Result<Vec<Self>, CacheVaultError> {
        let attributes = sqlx::query_as!(
            Attribute,
            r#"
              select
                id
              , entry_id
              , name
              , nonce
              , encrypted_value
              , hashed_value
              , created_at
              , updated_at
              from
                attributes
              where
                entry_id = $1
              order by
                id
            "#,
            entry_id
        )
        .fetch_all(&*POOL)
        .await?;
        Ok(attributes)
    }

    pub async fn upsert(entry_id: i64, name: &str, value: &str) -> Result<i64, CacheVaultError> {
        let (encrypted_value, nonce) = encrypt(value.to_string())?;
        let hashed_value = digest(value.as_bytes())?.to_vec();
        let id = sqlx::query!(
            r#"
              insert into
                attributes (entry_id, name, nonce, encrypted_value, hashed_value, created_at, updated_at)
                values ($1, $2, $3, $4, $5, datetime('now'), datetime('now'))
                on conflict(entry_id, name) do update set
                  nonce = $3
                , encrypted_value = $4
                , hashed_value = $5
                , updated_at = datetime('now')
            "#,
            entry_id,
            name,
            nonce,
            encrypted_value,
            hashed_value
        )
        .execute(&*POOL)
        .await
        .with_context(|| format!("failed to upsert attributes entry_id={:?} name={:?}", entry_id, name))?
        .last_insert_rowid();
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::migrate;

    #[tokio::test]
    async fn test_entry_fetch_no_such_key() -> Result<(), CacheVaultError> {
        let _ = migrate().await?;
        match Entry::fetch("test", "no-such-key").await {
            Err(e) => match e {
                CacheVaultError::SqlxError(sqlx::Error::RowNotFound) => (),
                _ => panic!("unexpected"),
            },
            Ok(_) => panic!("unexpected"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_attribute_fetch_all() -> Result<(), CacheVaultError> {
        let _ = migrate().await?;
        let entry_id = Entry::upsert("test", "test-key", "test-value", None).await?;

        let (envrypted_value0, nonce0) = encrypt(String::from("value0"))?;
        let (envrypted_value1, nonce1) = encrypt(String::from("value1"))?;
        let (envrypted_value2, nonce2) = encrypt(String::from("value2"))?;
        let hashed_value0 = digest(b"value0")?.to_vec();
        let hashed_value1 = digest(b"value1")?.to_vec();
        let hashed_value2 = digest(b"value2")?.to_vec();
        let _ = sqlx::query(
            r#"
              insert into
                attributes (entry_id, name, nonce, encrypted_value, hashed_value, created_at, updated_at)
                values ($1, "name0", $2, $3, $4, datetime('now'), datetime('now'))
                      ,($1, "name1", $5, $6, $7, datetime('now'), datetime('now'))
                      ,($1, "name2", $8, $9, $10, datetime('now'), datetime('now'))
            "#,
        )
        .bind(entry_id)
        .bind(nonce0)
        .bind(envrypted_value0)
        .bind(hashed_value0)
        .bind(nonce1)
        .bind(envrypted_value1)
        .bind(hashed_value1)
        .bind(nonce2)
        .bind(envrypted_value2)
        .bind(hashed_value2)
        .execute(&*POOL)
        .await?;

        let attributes = Attribute::fetch_all(entry_id).await?;
        assert_eq!(attributes.len(), 3);
        if let Some(a) = attributes.get(0) {
            assert_eq!(a.name, "name0");
            assert_eq!(a.plaintext()?, "value0");
        } else {
            panic!("failed to fetch attribute 0");
        }
        if let Some(a) = attributes.get(1) {
            assert_eq!(a.name, "name1");
            assert_eq!(a.plaintext()?, "value1");
        } else {
            panic!("failed to fetch attribute 1");
        }
        if let Some(a) = attributes.get(2) {
            assert_eq!(a.name, "name2");
            assert_eq!(a.plaintext()?, "value2");
        } else {
            panic!("failed to fetch attribute 2");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_upsert_entry_and_attribute() -> Result<(), CacheVaultError> {
        let _ = migrate().await?;
        let entry_id = Entry::upsert("test", "test-key", "test-value", None).await?;
        let e = Entry::fetch("test", "test-key").await?;
        assert_eq!(entry_id, e.id);
        assert_eq!(e.namespace, "test");
        assert_eq!(e.key_name, "test-key");
        assert_eq!(e.plaintext()?, "test-value");
        let entry_id2 = Entry::upsert("test", "test-key", "test-updated-value", None).await?;
        let e = Entry::fetch_by_id(entry_id2).await?;
        assert_eq!(entry_id, entry_id2);
        assert_eq!(entry_id, e.id);
        assert_eq!(e.namespace, "test");
        assert_eq!(e.key_name, "test-key");
        assert_eq!(e.plaintext()?, "test-updated-value");

        let attribute_id = Attribute::upsert(entry_id, "test-attribute", "test-attribute-value").await?;
        let a = Attribute::fetch_by_id(attribute_id).await?;
        assert_eq!(a.id, attribute_id);
        assert_eq!(a.entry_id, entry_id);
        assert_eq!(a.name, "test-attribute");
        assert_eq!(a.plaintext()?, "test-attribute-value");
        let attribute_id2 = Attribute::upsert(entry_id, "test-attribute", "test-updated-attribute-value").await?;
        let a = Attribute::fetch_by_id(attribute_id).await?;
        assert_eq!(attribute_id, attribute_id2);
        assert_eq!(a.id, attribute_id);
        assert_eq!(a.entry_id, entry_id);
        assert_eq!(a.name, "test-attribute");
        assert_eq!(a.plaintext()?, "test-updated-attribute-value");

        let a = Attribute::fetch_by_name(entry_id, "test-attribute").await?;
        assert_eq!(a.id, attribute_id);
        assert_eq!(a.entry_id, entry_id);
        assert_eq!(a.name, "test-attribute");
        assert_eq!(a.plaintext()?, "test-updated-attribute-value");
        Ok(())
    }
}
