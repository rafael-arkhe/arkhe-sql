# Row-Level Security (RLS)

Data access in `arkhe-sql` is strictly governed by PostgreSQL's Row-Level Security (RLS).

## Enforcement
RLS policies are not merely enabled; they are strictly enforced using `FORCE ROW LEVEL SECURITY`. This ensures that policies apply to all roles, including table owners.

## Application Runtime
To guarantee that RLS policies cannot be bypassed, the application runtime role must connect with the `NOSUPERUSER NOBYPASSRLS` attributes. This guarantees isolated and secure access paths for every operation.
