use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::sync::LazyLock;
use std::sync::OnceLock;

use crate::error::CacheVaultError;

#[allow(dead_code)]
static MIGRATOR: Migrator = sqlx::migrate!();

pub static POOL: LazyLock<SqlitePool> = LazyLock::new(|| {
    let options = SqliteConnectOptions::new()
        .filename(&*DB_PATH)
        .create_if_missing(true);
    let conn = SqlitePool::connect_lazy_with(options);
    conn
});

#[cfg(not(test))]
static DB_PATH: LazyLock<String> = LazyLock::new(|| {
    let config_dir = dirs::config_dir().expect("Unable to get default config directory");
    let default_db_path = config_dir
        .join("cache-vault/cache-vault.db")
        .to_str()
        .unwrap()
        .to_string();
    let db_path = std::env::var("CACHE_VAULT_DATABASE_PATH").unwrap_or(default_db_path);
    db_path
});

#[cfg(test)]
static DB_PATH: LazyLock<String> = LazyLock::new(|| {
    use tempfile::NamedTempFile;
    let file = NamedTempFile::new().unwrap();
    let path = String::from(file.path().to_string_lossy());
    let _ = file.close();
    path
});

#[allow(dead_code)]
static MIGRATED: OnceLock<bool> = OnceLock::new();

#[allow(dead_code)]
pub async fn migrate() -> Result<(), CacheVaultError> {
    if MIGRATED.get().is_none() {
        dbg!("migrate");
        MIGRATOR
            .run(&*POOL)
            .await
            .map_err(CacheVaultError::MigrateError)?;
        let _ = MIGRATED.set(true);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database() -> Result<(), CacheVaultError> {
        migrate().await?;
        let _ = sqlx::query(r#"select 1 as id"#).fetch_one(&*POOL).await?;
        Ok(())
    }
}
