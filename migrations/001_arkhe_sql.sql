-- 1. Tabela de eventos (append-only)
CREATE TABLE usage_events (
    request_id          UUID PRIMARY KEY,
    idempotency_key     TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    tool_name           TEXT NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms         BIGINT NOT NULL,
    result              TEXT NOT NULL CHECK (result IN ('PASS','FAIL','INCONCLUSIVE')),
    policy_digest       BYTEA,  -- nullable: nem toda a operação tem policy
    evidence_hash       BYTEA,  -- nullable
    estimated_cost_usd  NUMERIC(20,6) NOT NULL,
    billable_units      BIGINT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
) PARTITION BY RANGE (started_at);

-- Dummy tables para satisfazer dependências das grants em 20261017000001_init_roles.sql e outros scripts
CREATE TABLE verification_records (
    record_hash BYTEA PRIMARY KEY,
    intent_digest BYTEA,
    result TEXT,
    policy_digest BYTEA
);

CREATE TABLE intents (
    intent_digest BYTEA PRIMARY KEY
);

CREATE TABLE branch_states (
    branch_digest BYTEA PRIMARY KEY
);

CREATE TABLE finding_dispositions (
    disposition_digest BYTEA PRIMARY KEY
);
