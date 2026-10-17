CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only (attempted % on row %)',
        TG_TABLE_NAME, TG_OP, OLD
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER usage_events_no_update
    BEFORE UPDATE ON usage_events
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
CREATE TRIGGER usage_events_no_delete
    BEFORE DELETE ON usage_events
    FOR EACH ROW EXECUTE FUNCTION reject_mutation();
-- (idem para verification_records, intents, branch_states, finding_dispositions)