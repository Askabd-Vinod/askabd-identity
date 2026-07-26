import { randomUUID, createHash } from 'node:crypto';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { getSecurityConfig } from '../config/security.js';

export type IdentityType = 'human_user' | 'service_account' | 'api_client' | 'machine_identity' | 'federated_identity' | 'guest_user';
export type VerificationStatus = 'pending_verification' | 'active' | 'suspended' | 'deactivated' | 'deleted';

export interface Identity {
  id: string;
  identifier: string;
  orgContext: string;
  identityType: IdentityType;
  verificationStatus: VerificationStatus;
  profile: Record<string, unknown>;
  createdAt: Date;
}

export interface CreateIdentityInput {
  identifier: string;
  orgContext: string;
  identityType?: IdentityType;
  profile?: Record<string, unknown>;
}

export interface CreateIdentityResult {
  identity: Identity;
  verificationToken: string;
}

export interface VerifyIdentityInput {
  identityId: string;
  token: string;
}

export type Result<T, E = DomainError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export interface DomainError {
  category: 'validation' | 'conflict' | 'not_found' | 'authentication' | 'expired';
  code: string;
  field?: string;
  message: string;
}

const VALID_IDENTITY_TYPES: IdentityType[] = [
  'human_user', 'service_account', 'api_client', 'machine_identity', 'federated_identity', 'guest_user',
];

export class IdentityManager {
  constructor(
    private readonly db: DbClient,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
  ) {}

  async createIdentity(input: CreateIdentityInput): Promise<Result<CreateIdentityResult>> {
    if (!input.identifier || input.identifier.length < 1 || input.identifier.length > 255) {
      return { ok: false, error: { category: 'validation', code: 'identifier_length', field: 'identifier', message: 'identifier must be 1..255 characters' } };
    }
    if (!input.orgContext || input.orgContext.length < 1 || input.orgContext.length > 255) {
      return { ok: false, error: { category: 'validation', code: 'org_context_length', field: 'orgContext', message: 'org_context must be 1..255 characters' } };
    }
    const identityType = input.identityType ?? 'human_user';
    if (!VALID_IDENTITY_TYPES.includes(identityType)) {
      return { ok: false, error: { category: 'validation', code: 'invalid_identity_type', field: 'identityType', message: `identity_type must be one of: ${VALID_IDENTITY_TYPES.join(', ')}` } };
    }

    const existing = await this.db.query<{ id: string }>('SELECT id FROM identity WHERE org_context = $1 AND identifier = $2', [input.orgContext, input.identifier]);
    if (existing.rows.length > 0) {
      return { ok: false, error: { category: 'conflict', code: 'identifier_exists', field: 'identifier', message: 'An identity with this identifier already exists in this organization' } };
    }

    const id = randomUUID();
    const profile = input.profile ?? {};
    const result = await this.db.query<{ id: string; identifier: string; org_context: string; identity_type: string; verification_status: string; profile: Record<string, unknown>; created_at: Date }>(
      `INSERT INTO identity (id, identifier, org_context, identity_type, verification_status, profile) VALUES ($1, $2, $3, $4, 'pending_verification', $5) RETURNING id, identifier, org_context, identity_type, verification_status, profile, created_at`,
      [id, input.identifier, input.orgContext, identityType, JSON.stringify(profile)],
    );

    const row = result.rows[0]!;
    const identity: Identity = { id: row.id, identifier: row.identifier, orgContext: row.org_context, identityType: row.identity_type as IdentityType, verificationStatus: row.verification_status as VerificationStatus, profile: row.profile, createdAt: row.created_at };

    const verificationToken = await this.issueVerificationToken(identity.id);

    await this.auditLogger.record({ type: 'identity.created', identityId: identity.id, orgContext: input.orgContext, detail: { identifier: input.identifier, identityType } });
    await this.eventPublisher.publish('identity.created', input.orgContext, { identityId: identity.id, identifier: input.identifier, identityType });

    return { ok: true, value: { identity, verificationToken } };
  }

  private async issueVerificationToken(identityId: string): Promise<string> {
    const config = getSecurityConfig();
    const token = randomUUID();
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + config.verificationTokenExpirySec * 1000);
    await this.db.query('INSERT INTO verification_token (identity_id, token_hash, expires_at) VALUES ($1, $2, $3)', [identityId, tokenHash, expiresAt]);
    return token;
  }

  async verify(input: VerifyIdentityInput): Promise<Result<{ identity: Identity }>> {
    if (!input.identityId || !input.token) {
      return { ok: false, error: { category: 'validation', code: 'missing_fields', message: 'identityId and token are required' } };
    }
    const tokenHash = createHash('sha256').update(input.token).digest('hex');
    const tokenResult = await this.db.query<{ id: string; identity_id: string; expires_at: Date; consumed: boolean }>(
      'SELECT id, identity_id, expires_at, consumed FROM verification_token WHERE identity_id = $1 AND token_hash = $2 ORDER BY created_at DESC LIMIT 1',
      [input.identityId, tokenHash],
    );
    if (tokenResult.rows.length === 0) {
      return { ok: false, error: { category: 'authentication', code: 'invalid_token', message: 'Verification token is invalid' } };
    }
    const tokenRow = tokenResult.rows[0]!;
    if (tokenRow.consumed) {
      return { ok: false, error: { category: 'authentication', code: 'token_consumed', message: 'Verification token has already been used' } };
    }
    if (new Date() > tokenRow.expires_at) {
      return { ok: false, error: { category: 'expired', code: 'token_expired', message: 'Verification token has expired' } };
    }

    await this.db.query('UPDATE verification_token SET consumed = TRUE WHERE id = $1', [tokenRow.id]);
    await this.db.query(`UPDATE identity SET verification_status = 'active', updated_at = NOW() WHERE id = $1`, [input.identityId]);

    const identityResult = await this.db.query<{ id: string; identifier: string; org_context: string; identity_type: string; verification_status: string; profile: Record<string, unknown>; created_at: Date }>(
      'SELECT id, identifier, org_context, identity_type, verification_status, profile, created_at FROM identity WHERE id = $1',
      [input.identityId],
    );
    const row = identityResult.rows[0]!;
    const identity: Identity = { id: row.id, identifier: row.identifier, orgContext: row.org_context, identityType: row.identity_type as IdentityType, verificationStatus: row.verification_status as VerificationStatus, profile: row.profile, createdAt: row.created_at };

    await this.auditLogger.record({ type: 'identity.verified', identityId: identity.id, orgContext: identity.orgContext });
    await this.eventPublisher.publish('identity.verified', identity.orgContext, { identityId: identity.id });

    return { ok: true, value: { identity } };
  }

  async getById(identityId: string, orgContext: string): Promise<Identity | null> {
    const result = await this.db.query<{ id: string; identifier: string; org_context: string; identity_type: string; verification_status: string; profile: Record<string, unknown>; created_at: Date }>(
      'SELECT id, identifier, org_context, identity_type, verification_status, profile, created_at FROM identity WHERE id = $1 AND org_context = $2',
      [identityId, orgContext],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0]!;
    return { id: row.id, identifier: row.identifier, orgContext: row.org_context, identityType: row.identity_type as IdentityType, verificationStatus: row.verification_status as VerificationStatus, profile: row.profile, createdAt: row.created_at };
  }

  async getByIdentifier(identifier: string, orgContext: string): Promise<Identity | null> {
    const result = await this.db.query<{ id: string; identifier: string; org_context: string; identity_type: string; verification_status: string; profile: Record<string, unknown>; created_at: Date }>(
      'SELECT id, identifier, org_context, identity_type, verification_status, profile, created_at FROM identity WHERE identifier = $1 AND org_context = $2',
      [identifier, orgContext],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0]!;
    return { id: row.id, identifier: row.identifier, orgContext: row.org_context, identityType: row.identity_type as IdentityType, verificationStatus: row.verification_status as VerificationStatus, profile: row.profile, createdAt: row.created_at };
  }
}
