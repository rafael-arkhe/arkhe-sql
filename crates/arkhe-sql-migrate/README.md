# arkhe-sql-migrate

`arkhe-sql-migrate` is a specialized CLI tool for the `arkhe-sql` workspace.

Built on top of SQLx, this crate manages database migrations with an emphasis on immutability. It utilizes SHA-384 checksums to guarantee that migration scripts are never modified after publication.
