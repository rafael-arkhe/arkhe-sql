# Migration Discipline

Database migrations in `arkhe-sql` are treated with the same immutability guarantees as the data itself.

## SHA-384 Checksums
Every migration script is locked with an immutable SHA-384 checksum upon creation.

## CLI Tool
Migrations are strictly managed via the `arkhe-sql-migrate` CLI crate (powered by SQLx). The tool verifies the checksums before applying any changes. This guarantees that once a migration is published and applied, it can never be altered retroactively.
