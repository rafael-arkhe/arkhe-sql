# arkhe-sql

`arkhe-sql` is a Rust and SQLx workspace that serves as an immutable evidence ledger and persistence layer using PostgreSQL.

## Features

- **Append-Only Event Store**: The database architecture strictly enforces append-only storage. `UPDATE` and `DELETE` operations are prohibited via privilege revocation (the `arkhe_append` role only has `INSERT`/`SELECT`) and trigger backstops.
- **CQRS Pattern**: The project implements the Command Query Responsibility Segregation (CQRS) pattern, using an append-only event store as the source of truth and read-only materialized views for querying.
- **Merkle Mountain Range (MMR)**: An MMR structure is used for authenticated append-only data, utilizing periodic checkpoints for incremental verification.
- **Strict Row-Level Security (RLS)**: RLS is strictly enforced using `ENABLE` and `FORCE ROW LEVEL SECURITY`. The application runtime role must always be `NOSUPERUSER NOBYPASSRLS`.
- **Immutable Migrations**: Database migrations are managed via SQLx (through the `arkhe-sql-migrate` CLI crate) and rely on immutable SHA-384 checksums to guarantee migrations are never edited after publication.

## Prerequisites

- PostgreSQL 16
- Rust (latest stable)
- Docker and Docker Compose (for local development)

## Getting Started

Local development and testing require PostgreSQL 16, which is orchestrated via `docker-compose`.

To start the database:
```bash
docker-compose up -d
```

To run migrations, use the provided CLI tool:
```bash
cargo run --bin arkhe-sql-migrate
```

## Documentation

For more detailed technical documentation, please refer to the files in the `docs/` folder:
- [Architecture](docs/architecture.md)
- [Append-Only Constraints](docs/append-only.md)
- [CQRS & Projections](docs/cqrs-projections.md)
- [Idempotency](docs/idempotency.md)
- [Migration Discipline](docs/migration-discipline.md)
- [MMR Checkpoints](docs/mmr-checkpoints.md)
- [Row-Level Security (RLS)](docs/rls.md)
- [Roles & Privileges](docs/roles-and-privileges.md)

## Crate Structure

- `crates/arkhe-sql`: Core library for the immutable evidence ledger and persistence layer.
- `crates/arkhe-sql-migrate`: CLI tool for managing immutable database migrations.

## License

This project is licensed under the terms found in the LICENSE file.
