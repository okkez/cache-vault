use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::sync::LazyLock;
use std::sync::OnceLock;

use crate::error::CacheVaultError;

#[allow(dead_code)]
static MIGRATOR: Migrator = sqlx::migrate!();

pub static POOL: LazyLock<Result<SqlitePool, CacheVaultError>> = LazyLock::new(|| {
    let db_path = DB_PATH.as_ref().map_err(|e| e.clone())?; // Clone the error if necessary or ensure Error type implements Clone
    let options = SqliteConnectOptions::new().filename(db_path).create_if_missing(true);
    let conn = SqlitePool::connect_lazy_with(options);
    Ok(conn)
});

#[cfg(not(test))]
static DB_PATH: LazyLock<Result<String, CacheVaultError>> = LazyLock::new(|| {
    let config_dir = dirs::config_dir().ok_or(CacheVaultError::ConfigDirectoryNotFound)?;
    let default_db_path = config_dir
        .join("cache-vault/cache-vault.db")
        .to_str()
        .ok_or_else(|| CacheVaultError::Unknown("Unable to convert path to string".to_string()))?
        .to_string();
    let db_path = std::env::var("CACHE_VAULT_DATABASE_PATH").unwrap_or(default_db_path);
    let db_dir = std::path::Path::new(&db_path)
        .parent()
        .ok_or_else(|| CacheVaultError::Unknown("Unable to get cache-vault directory".to_string()))?;
    std::fs::create_dir_all(db_dir)
        .map_err(|e| CacheVaultError::Unknown(format!("Unable to create cache-vault directory: {}", e)))?;
    tracing::debug!(name: "cache-vault", "DB_PATH: {}", &db_path);
    Ok(db_path)
});

#[cfg(test)]
static DB_PATH: LazyLock<Result<String, CacheVaultError>> = LazyLock::new(|| {
    use tempfile::NamedTempFile;
    let file = NamedTempFile::new().unwrap();
    let path = String::from(file.path().to_string_lossy());
    let _ = file.close();
    tracing::info!("DB_PATH: {}", path);
    Ok(path)
});

#[allow(dead_code)]
static MIGRATED: OnceLock<bool> = OnceLock::new();

#[allow(dead_code)]
#[tracing::instrument]
pub async fn migrate() -> Result<(), CacheVaultError> {
    if MIGRATED.get().is_none() {
        tracing::debug!("migrate");
        let pool = POOL.as_ref().map_err(|e| e.clone())?;
        MIGRATOR.run(pool).await.map_err(CacheVaultError::MigrateError)?;
        let _ = MIGRATED.set(true);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_database() -> Result<(), CacheVaultError> {
        migrate().await?;
        let pool = POOL.as_ref().map_err(|e| e.clone())?;
        let _ = sqlx::query(r#"select 1 as id"#).fetch_one(pool).await?;
        Ok(())
    }
}
