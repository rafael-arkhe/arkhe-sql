# CQRS & Projections

The system is built on the Command Query Responsibility Segregation (CQRS) pattern.

## Event Store
The event store acts as the single, append-only source of truth. Commands write new events to this store without modifying existing state.

## Materialized Views
To facilitate efficient reads, read-only materialized views (projections) are utilized. These views are updated asynchronously or synchronously based on the event log, decoupling complex query requirements from the fast, append-only write path.
