CREATE MATERIALIZED VIEW tenant_usage_daily AS
SELECT tenant_id, DATE_TRUNC('day', started_at) AS day,
       COUNT(*) AS verifications,
       SUM(estimated_cost_usd) AS cost
FROM usage_events
GROUP BY tenant_id, day;

CREATE UNIQUE INDEX ON tenant_usage_daily (tenant_id, day);

CREATE MATERIALIZED VIEW verification_outcomes AS
SELECT tenant_id, policy_digest, result, COUNT(*) AS n
FROM verification_records
GROUP BY tenant_id, policy_digest, result;