# Merkle Mountain Range (MMR) Checkpoints

To provide cryptographic proof of data integrity and sequence, `arkhe-sql` employs a Merkle Mountain Range (MMR) structure for authenticated append-only data.

## Periodic Checkpoints
Instead of verifying the entire chain for every read, the system creates periodic MMR checkpoints. These checkpoints allow for efficient, incremental verification of the ledger's state without the overhead of scanning the full historical log.
