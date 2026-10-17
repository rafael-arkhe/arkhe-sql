ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;

CREATE FUNCTION arkhe_assert_tenant() RETURNS text AS $$
DECLARE tid text := current_setting('app.tenant_id', true);
BEGIN
    IF tid IS NULL OR tid = '' THEN
        RAISE EXCEPTION 'app.tenant_id is not set'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN tid;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE POLICY tenant_isolation ON usage_events
    USING (tenant_id = arkhe_assert_tenant())
    WITH CHECK (tenant_id = arkhe_assert_tenant());