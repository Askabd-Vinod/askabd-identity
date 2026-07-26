import { randomUUID, createHash } from 'node:crypto';
import argon2 from 'argon2';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result, type DomainError } from './identity-manager.js';

const KNOWN_BREACHED = new Set(['password', 'password123', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'master', 'hello', 'shadow']);

export class CredentialManager {
  constructor(
    private readonly db: DbClient,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
  ) {}

  async storeCredential(identityId: string, credential: string, orgContext: string): Promise<Result<void>> {
    const complexityError = this.checkComplexity(credential);
    if (complexityError) return { ok: false, error: complexityError };
    if (this.isBreached(credential)) {
      return { ok: false, error: { category: 'validation', code: 'credential_breached', field: 'credential', message: 'This password appears in known data breaches.' } };
    }
    const hash = await this.hashCredential(credential);
    await this.db.query(
      `INSERT INTO credential (identity_id, hash, algo, updated_at) VALUES ($1, $2, 'argon2id', NOW()) ON CONFLICT (identity_id) DO UPDATE SET hash = $2, algo = 'argon2id', updated_at = NOW()`,
      [identityId, hash],
    );
    await this.auditLogger.record({ type: 'credential.stored', identityId, orgContext, detail: { algo: 'argon2id' } });
    return { ok: true, value: undefined };
  }

  async changeCredential(input: { identityId: string; currentCredential: string; newCredential: string; orgContext: string; sessionId?: string }): Promise<Result<void>> {
    const currentHash = await this.getStoredHash(input.identityId);
    if (!currentHash) return { ok: false, error: { category: 'authentication', code: 'no_credential', message: 'No credential exists for this identity' } };
    const matches = await argon2.verify(currentHash, input.currentCredential);
    if (!matches) return { ok: false, error: { category: 'authentication', code: 'credential_mismatch', message: 'Current credential does not match' } };
    if (input.currentCredential === input.newCredential) return { ok: false, error: { category: 'validation', code: 'credential_same', field: 'newCredential', message: 'New credential must differ from current' } };
    const complexityError = this.checkComplexity(input.newCredential);
    if (complexityError) return { ok: false, error: complexityError };
    if (this.isBreached(input.newCredential)) return { ok: false, error: { category: 'validation', code: 'credential_breached', field: 'newCredential', message: 'This password appears in known data breaches.' } };
    const newHash = await this.hashCredential(input.newCredential);
    await this.db.query(`UPDATE credential SET hash = $1, algo = 'argon2id', updated_at = NOW() WHERE identity_id = $2`, [newHash, input.identityId]);
    if (input.sessionId) {
      await this.db.query(`UPDATE session SET status = 'terminated' WHERE identity_id = $1 AND id != $2 AND status = 'active'`, [input.identityId, input.sessionId]);
    }
    await this.auditLogger.record({ type: 'credential.changed', identityId: input.identityId, orgContext: input.orgContext, detail: { algo: 'argon2id' } });
    await this.eventPublisher.publish('credential.changed', input.orgContext, { identityId: input.identityId });
    return { ok: true, value: undefined };
  }

  async issueResetToken(identityId: string | null, orgContext: string): Promise<{ token: string | null }> {
    if (!identityId) return { token: null };
    const config = getSecurityConfig();
    const token = randomUUID();
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + config.resetTokenExpirySec * 1000);
    await this.db.query('INSERT INTO reset_token (identity_id, token_hash, expires_at) VALUES ($1, $2, $3)', [identityId, tokenHash, expiresAt]);
    await this.auditLogger.record({ type: 'credential.reset_requested', identityId, orgContext });
    return { token };
  }

  async resetCredential(input: { token: string; newCredential: string; orgContext: string }): Promise<Result<{ identityId: string }>> {
    const tokenHash = createHash('sha256').update(input.token).digest('hex');
    const tokenResult = await this.db.query<{ id: string; identity_id: string; expires_at: Date; consumed: boolean }>(
      'SELECT id, identity_id, expires_at, consumed FROM reset_token WHERE token_hash = $1 ORDER BY created_at DESC LIMIT 1', [tokenHash]);
    if (tokenResult.rows.length === 0) return { ok: false, error: { category: 'authentication', code: 'invalid_token', message: 'Reset token is invalid' } };
    const tokenRow = tokenResult.rows[0]!;
    if (tokenRow.consumed) return { ok: false, error: { category: 'authentication', code: 'token_consumed', message: 'Reset token has already been used' } };
    if (new Date() > tokenRow.expires_at) return { ok: false, error: { category: 'expired', code: 'token_expired', message: 'Reset token has expired' } };
    const complexityError = this.checkComplexity(input.newCredential);
    if (complexityError) return { ok: false, error: complexityError };
    if (this.isBreached(input.newCredential)) return { ok: false, error: { category: 'validation', code: 'credential_breached', field: 'newCredential', message: 'This password appears in known data breaches.' } };
    await this.db.query('UPDATE reset_token SET consumed = TRUE WHERE id = $1', [tokenRow.id]);
    const newHash = await this.hashCredential(input.newCredential);
    await this.db.query(`INSERT INTO credential (identity_id, hash, algo, updated_at) VALUES ($1, $2, 'argon2id', NOW()) ON CONFLICT (identity_id) DO UPDATE SET hash = $2, algo = 'argon2id', updated_at = NOW()`, [tokenRow.identity_id, newHash]);
    await this.db.query(`UPDATE session SET status = 'terminated' WHERE identity_id = $1 AND status = 'active'`, [tokenRow.identity_id]);
    await this.auditLogger.record({ type: 'credential.reset', identityId: tokenRow.identity_id, orgContext: input.orgContext });
    await this.eventPublisher.publish('credential.reset', input.orgContext, { identityId: tokenRow.identity_id });
    return { ok: true, value: { identityId: tokenRow.identity_id } };
  }

  async verifyCredential(identityId: string, credential: string): Promise<boolean> {
    const hash = await this.getStoredHash(identityId);
    if (!hash) return false;
    return argon2.verify(hash, credential);
  }

  private checkComplexity(credential: string): DomainError | null {
    const config = getSecurityConfig();
    if (credential.length < config.credentialMinLength) return { category: 'validation', code: 'credential_too_short', field: 'credential', message: `Password must be at least ${config.credentialMinLength} characters` };
    if (credential.length > config.credentialMaxAcceptLength) return { category: 'validation', code: 'credential_too_long', field: 'credential', message: `Password must not exceed ${config.credentialMaxAcceptLength} characters` };
    return null;
  }

  private isBreached(credential: string): boolean {
    const config = getSecurityConfig();
    if (!config.credentialRequireBreachCheck) return false;
    return KNOWN_BREACHED.has(credential.toLowerCase());
  }

  private async hashCredential(credential: string): Promise<string> {
    const config = getSecurityConfig();
    return argon2.hash(credential, { type: argon2.argon2id, memoryCost: config.argon2MemoryCostKb, timeCost: config.argon2TimeCost, parallelism: config.argon2Parallelism });
  }

  private async getStoredHash(identityId: string): Promise<string | null> {
    const result = await this.db.query<{ hash: string }>('SELECT hash FROM credential WHERE identity_id = $1', [identityId]);
    return result.rows[0]?.hash ?? null;
  }
}
