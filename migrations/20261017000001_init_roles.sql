-- Role de runtime: só INSERT e SELECT nas tabelas de evidência
CREATE ROLE arkhe_append LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO arkhe_append;
GRANT INSERT, SELECT ON usage_events, verification_records, intents,
    branch_states, finding_dispositions, mmr_checkpoints TO arkhe_append;

-- Role de leitura: só SELECT
CREATE ROLE arkhe_read LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO arkhe_read;

-- Role de migração: owner das tabelas, usada apenas por arkhe-sql-migrate
CREATE ROLE arkhe_admin LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT ALL PRIVILEGES ON SCHEMA public TO arkhe_admin;