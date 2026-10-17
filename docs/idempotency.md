# Idempotency

In distributed systems and event-driven architectures, messages may be delivered more than once. `arkhe-sql` employs strict idempotency mechanisms to safely handle retries and duplicate operations.

## Unique Keys
Idempotency is enforced at the database level using unique constraint keys. When a command is issued, it includes an idempotency key. If an `INSERT` is attempted with a previously processed key, the database gracefully handles the conflict, ensuring the operation is not duplicated and maintaining the ledger's integrity.
