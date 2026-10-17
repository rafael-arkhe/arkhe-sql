use sqlx::PgConnection;
use std::future::Future;

#[derive(Debug)]
pub enum ArkheSqlError {
    Database(sqlx::Error),
}

impl From<sqlx::Error> for ArkheSqlError {
    fn from(err: sqlx::Error) -> Self {
        ArkheSqlError::Database(err)
    }
}

pub async fn with_tenant<T, F, Fut>(
    conn: &mut PgConnection,
    tenant_id: &str,
    f: F,
) -> Result<T, ArkheSqlError>
where
    F: FnOnce(&mut PgConnection) -> Fut,
    Fut: Future<Output = Result<T, ArkheSqlError>>,
{
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;
    f(conn).await
}