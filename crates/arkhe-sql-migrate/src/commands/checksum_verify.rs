use sha2::{Sha384, Digest};
use std::path::Path;

#[derive(Debug)]
pub struct MigrationChecksumMismatch {
    pub version: String,
}

pub async fn verify_checksums(pool: sqlx::PgPool, migrations_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let applied: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations")
            .fetch_all(&pool).await?;

    for (version, stored_checksum) in applied {
        let path = migrations_dir.join(format!("{}.sql", version));
        let content = tokio::fs::read(&path).await?;

        let mut hasher = Sha384::new();
        hasher.update(&content);
        let disk_checksum = hasher.finalize().to_vec();

        if disk_checksum != stored_checksum {
            return Err(Box::new(MigrationChecksumMismatch { version }));
        }
    }

    Ok(())
}

impl std::fmt::Display for MigrationChecksumMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checksum mismatch for migration {}", self.version)
    }
}
impl std::error::Error for MigrationChecksumMismatch {}