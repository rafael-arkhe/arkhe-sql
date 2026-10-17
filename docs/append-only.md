# Append-Only Constraints

To ensure the integrity of the ledger, the database architecture strictly enforces an append-only model.

## Mechanisms

1. **Privilege Revocation:** The runtime role (e.g., `arkhe_append`) is only granted `INSERT` and `SELECT` privileges. `UPDATE` and `DELETE` commands will fail at the authorization layer.
2. **Trigger Backstops:** As a defense-in-depth measure, PostgreSQL triggers are employed to actively intercept and abort any attempted `UPDATE` or `DELETE` operations on append-only tables, preventing modifications even if role privileges are accidentally escalated.

These guarantees ensure historical data can never be tampered with.
