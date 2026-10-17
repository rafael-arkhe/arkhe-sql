# Contributing

We welcome contributions to `arkhe-sql`!

## Local Setup

To develop and run tests locally, you must use PostgreSQL 16. The environment is orchestrated via Docker Compose.

1. Start the required services:
   ```bash
   docker-compose up -d
   ```
2. Ensure you have the latest stable Rust toolchain installed.
3. Run migrations and tests to verify the setup:
   ```bash
   cargo test
   ```

## Guidelines
- Write tests for any new functionality or bug fixes.
- Ensure all tests and linting (`cargo clippy`, `cargo fmt`) pass before opening a Pull Request.
- Document any significant architecture or behavioral changes in the `docs/` folder.
