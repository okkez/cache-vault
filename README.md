# cache-vault

This crate can store encrypted values to SQLite database. Encryption/decryption process are hidden in the crate.

Internally, cache-vault relies on the [keyring](https://crates.io/crates/keyring) crate and defaults to linux-keyutils when running in a headless environment.

## Usage

Cargo.toml:
```toml
[dependencies]
cache-vault = { version = "0.1.0" }
```

1. Initialize the database (cache)
2. Fetch data from the database (cache)
3. Check data expiration if data found
4. Use cached value or original value

```rust
pub async execute() -> Result<()> {
    // create database at ~/.config/cache-vault/cache-vault.db by default
    cache_vault::init().await?;
    let now = chrono::Utc::now().naive_utc();
    let found = match cache_vault::fetch("your application name", "unique-key-name").await {
        Err(_e) => None,           // The encrypted value does not found in SQListe database or something wrong
        Ok((value, None)) => None,  // w/o expired_at
        Ok((value, Some(expired_at))) => match now.cmp(&expired_at) {
            Ordering::Greater | Ordering::Equal => None,
            Ordering::Less => Some(value),
        }
    };
    match found {
        Some(value) => {
            // use cached value
        },
        None => {
            let value; // build value to be cached
            let expired_at = chrono::Utc::now().naive_utc().checked_add_signed(chrono::TimeDelta::try_hours(1).unwrap()).unwrap();
            cache_vault::save(
                "your application_name",
                "unique-key-name",
                &value,
                None,
                Some(expired_at),
            ).await.expect("Unable to save value to the database");
            // use original value below ...
        }
    };
}
```

## Database schema

```rust
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
```

## TODO

- Support multi-platform
- Search by attribute with forward matching
