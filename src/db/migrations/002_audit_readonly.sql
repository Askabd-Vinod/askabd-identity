-- Migration 002: Enforce append-only audit_event
-- The app-level DB role can only INSERT and SELECT on audit_event.
-- UPDATE and DELETE are explicitly revoked (R16.2, R16.3).

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'identity_app') THEN
    CREATE ROLE identity_app WITH LOGIN PASSWORD 'identity_app_pass';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO identity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO identity_app;
REVOKE UPDATE, DELETE ON audit_event FROM identity_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identity_app;

COMMIT;
