-- Migration 001: Initial Schema
-- Creates all tables for the Identity Platform per the ER diagram
-- Enforces tenant isolation via org_context scoping

BEGIN;

CREATE TABLE identity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier VARCHAR(255) NOT NULL,
  org_context VARCHAR(255) NOT NULL,
  identity_type VARCHAR(50) NOT NULL DEFAULT 'human_user'
    CHECK (identity_type IN ('human_user', 'service_account', 'api_client', 'machine_identity', 'federated_identity', 'guest_user')),
  verification_status VARCHAR(30) NOT NULL DEFAULT 'pending_verification'
    CHECK (verification_status IN ('pending_verification', 'active', 'suspended', 'deactivated', 'deleted')),
  profile JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_context, identifier)
);

CREATE INDEX idx_identity_org ON identity (org_context);
CREATE INDEX idx_identity_status ON identity (org_context, verification_status);

CREATE TABLE credential (
  identity_id UUID PRIMARY KEY REFERENCES identity(id) ON DELETE CASCADE,
  hash TEXT NOT NULL,
  algo VARCHAR(30) NOT NULL DEFAULT 'argon2id',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE verification_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id UUID NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_token_identity ON verification_token (identity_id);

CREATE TABLE reset_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id UUID NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reset_token_identity ON reset_token (identity_id);

CREATE TABLE session (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id UUID NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  org_context VARCHAR(255) NOT NULL,
  client_meta JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'terminated', 'expired'))
);

CREATE INDEX idx_session_identity ON session (identity_id, org_context);
CREATE INDEX idx_session_status ON session (status, identity_id);

CREATE TABLE access_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_access_token_session ON access_token (session_id);

CREATE TABLE refresh_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  prev_token_id UUID REFERENCES refresh_token(id),
  expires_at TIMESTAMPTZ NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'rotated', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_token_session ON refresh_token (session_id);
CREATE INDEX idx_refresh_token_hash ON refresh_token (token_hash);

CREATE TABLE role (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  org_context VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_context, name)
);

CREATE TABLE permission (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action VARCHAR(255) NOT NULL,
  resource_type VARCHAR(255) NOT NULL,
  org_context VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (org_context, action, resource_type)
);

CREATE TABLE role_permission (
  role_id UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permission(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE role_assignment (
  identity_id UUID NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
  org_context VARCHAR(255) NOT NULL,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (identity_id, role_id, org_context)
);

CREATE INDEX idx_role_assignment_identity ON role_assignment (identity_id, org_context);

CREATE TABLE mfa_method (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id UUID NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  type VARCHAR(30) NOT NULL DEFAULT 'totp'
    CHECK (type IN ('totp', 'sms', 'push', 'fido2', 'email')),
  secret_enc TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_method_identity ON mfa_method (identity_id);

CREATE TABLE audit_event (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type VARCHAR(100) NOT NULL,
  identity_id UUID,
  org_context VARCHAR(255),
  at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  detail JSONB DEFAULT '{}'
);

CREATE INDEX idx_audit_event_org_time ON audit_event (org_context, at);
CREATE INDEX idx_audit_event_identity ON audit_event (identity_id, at);

CREATE TABLE webhook_registration (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url TEXT NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  org_context VARCHAR(255) NOT NULL,
  signing_secret_enc TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_org ON webhook_registration (org_context, event_type);

CREATE TABLE lockout_state (
  identity_id UUID PRIMARY KEY REFERENCES identity(id) ON DELETE CASCADE,
  consecutive_failures INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ
);

COMMIT;
