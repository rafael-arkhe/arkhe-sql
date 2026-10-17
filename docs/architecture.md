# Architecture

`arkhe-sql` is a Rust and SQLx workspace serving as an immutable evidence ledger and persistence layer on top of PostgreSQL.

The architecture strictly follows:
- **Append-Only Event Sourcing:** Immutable logs as the primary source of truth.
- **CQRS (Command Query Responsibility Segregation):** Separation of event writing and projection querying.
- **Cryptographic Verification:** Using Merkle Mountain Ranges (MMR) for authenticated data.
- **Strict Database Security:** Leveraging Row-Level Security (RLS) and restricted roles to guarantee data immutability.

## Crates

- `arkhe-sql`: The core library for interacting with the database, exposing safe APIs that respect the ledger's invariants.
- `arkhe-sql-migrate`: A specialized CLI tool for running and managing database migrations immutably.
