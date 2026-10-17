CREATE TABLE mmr_checkpoints (
    checkpoint_id       BIGSERIAL PRIMARY KEY,
    covered_up_to_hash  BYTEA NOT NULL,          -- último record_hash coberto
    covered_count       BIGINT NOT NULL,
    mmr_root            BYTEA NOT NULL,
    peaks               BYTEA[] NOT NULL,
    profile_digest      BYTEA NOT NULL,          -- digest do MMRProfile v1
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Append-only triggers aplicam-se aqui também.