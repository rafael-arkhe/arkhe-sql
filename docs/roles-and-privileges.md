# Roles & Privileges

To maintain the principles of least privilege and strict append-only constraints, `arkhe-sql` employs specific database roles.

## Runtime Roles

- `arkhe_append`: This role is explicitly granted only `INSERT` and `SELECT` privileges. It is strictly used for writing to the event log and reading projections, guaranteeing no `UPDATE` or `DELETE` actions can be initiated from the application layer.

## Connection Constraints
The application must never connect as a superuser. Connections are enforced to run with `NOSUPERUSER NOBYPASSRLS`, ensuring Row-Level Security (RLS) and operational constraints are universally applied.
