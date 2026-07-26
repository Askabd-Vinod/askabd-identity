import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { CredentialManager } from './credential-manager.js';
import { SessionManager } from './session-manager.js';
import { TokenService } from './token-service.js';
import { MfaService } from './mfa-service.js';
import { RateLimiter } from './rate-limiter.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result, type DomainError } from './identity-manager.js';

export interface LoginInput {
  identifier: string; credential: string; orgContext: string;
  clientMeta?: Record<string, unknown>; mfaCode?: string; clientId?: string;
}

export type LoginResult =
  | { type: 'success'; accessToken: string; refreshToken: string; sessionId: string }
  | { type: 'mfa_required'; challengeId: string };

const AUTH_ERROR: DomainError = { category: 'authentication', code: 'authentication_failed', message: 'The credentials provided are invalid' };
const RATE_LIMITED_ERROR = (retryAfterMs: number): DomainError => ({ category: 'rate_limited' as any, code: 'rate_limited', message: 'Too many requests', retryAfterMs });

export class AuthService {
  constructor(
    private readonly db: DbClient, private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher, private readonly credentialManager: CredentialManager,
    private readonly sessionManager: SessionManager, private readonly tokenService: TokenService,
    private readonly mfaService: MfaService, private readonly rateLimiter: RateLimiter,
  ) {}

  async login(input: LoginInput): Promise<Result<LoginResult>> {
    const clientId = input.clientId ?? input.identifier;
    const rateResult = this.rateLimiter.check(clientId);
    if (!rateResult.allowed) {
      await this.auditLogger.record({ type: 'auth.rate_limited', orgContext: input.orgContext, detail: { clientId } });
      return { ok: false, error: RATE_LIMITED_ERROR(rateResult.retryAfterMs!) };
    }
    const lockout = await this.getLockoutState(input.identifier, input.orgContext);
    if (lockout.locked) {
      await this.auditLogger.record({ type: 'auth.login.failed', orgContext: input.orgContext, detail: { reason: 'locked' } });
      return { ok: false, error: AUTH_ERROR };
    }
    const identity = await this.findIdentity(input.identifier, input.orgContext);
    if (!identity) {
      await this.incrementFailures(input.identifier, input.orgContext);
      await this.auditLogger.record({ type: 'auth.login.failed', orgContext: input.orgContext, detail: { reason: 'unknown_identifier' } });
      return { ok: false, error: AUTH_ERROR };
    }
    if (identity.verification_status !== 'active') {
      await this.incrementFailures(input.identifier, input.orgContext);
      await this.auditLogger.record({ type: 'auth.login.failed', identityId: identity.id, orgContext: input.orgContext, detail: { reason: 'not_verified' } });
      return { ok: false, error: AUTH_ERROR };
    }
    const credentialValid = await this.credentialManager.verifyCredential(identity.id, input.credential);
    if (!credentialValid) {
      await this.incrementFailures(input.identifier, input.orgContext);
      await this.auditLogger.record({ type: 'auth.login.failed', identityId: identity.id, orgContext: input.orgContext, detail: { reason: 'credential_mismatch' } });
      return { ok: false, error: AUTH_ERROR };
    }
    const mfaActive = await this.mfaService.isActive(identity.id);
    if (mfaActive) {
      if (!input.mfaCode) return { ok: true, value: { type: 'mfa_required', challengeId: `challenge_${identity.id}` } };
      const mfaResult = await this.mfaService.challenge(identity.id, input.mfaCode);
      if (!mfaResult.ok) {
        await this.auditLogger.record({ type: 'auth.login.failed', identityId: identity.id, orgContext: input.orgContext, detail: { reason: 'mfa_failed' } });
        return { ok: false, error: AUTH_ERROR };
      }
    }
    await this.resetFailures(input.identifier, input.orgContext);
    const session = await this.sessionManager.create({ identityId: identity.id, orgContext: input.orgContext, clientMeta: input.clientMeta });
    const tokens = await this.tokenService.issueForSession(session.id, identity.id, input.orgContext);
    await this.auditLogger.record({ type: 'auth.login.succeeded', identityId: identity.id, orgContext: input.orgContext, detail: { sessionId: session.id } });
    return { ok: true, value: { type: 'success', accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, sessionId: session.id } };
  }

  async logout(sessionId: string, orgContext: string): Promise<Result<void>> {
    const result = await this.sessionManager.terminate(sessionId);
    if (!result.ok) return result;
    await this.auditLogger.record({ type: 'auth.logout', orgContext, detail: { sessionId } });
    return { ok: true, value: undefined };
  }

  private async getLockoutState(identifier: string, orgContext: string): Promise<{ locked: boolean }> {
    const identity = await this.findIdentity(identifier, orgContext);
    if (!identity) return { locked: false };
    const result = await this.db.query<{ consecutive_failures: number; locked_until: Date | null }>('SELECT consecutive_failures, locked_until FROM lockout_state WHERE identity_id = $1', [identity.id]);
    if (result.rows.length === 0) return { locked: false };
    const row = result.rows[0]!;
    if (row.locked_until && new Date() < row.locked_until) return { locked: true };
    if (row.locked_until && new Date() >= row.locked_until) {
      await this.db.query('UPDATE lockout_state SET consecutive_failures = 0, locked_until = NULL WHERE identity_id = $1', [identity.id]);
      return { locked: false };
    }
    return { locked: false };
  }

  private async incrementFailures(identifier: string, orgContext: string): Promise<void> {
    const config = getSecurityConfig();
    const identity = await this.findIdentity(identifier, orgContext);
    if (!identity) return;
    const result = await this.db.query<{ consecutive_failures: number }>(
      `INSERT INTO lockout_state (identity_id, consecutive_failures, locked_until) VALUES ($1, 1, NULL) ON CONFLICT (identity_id) DO UPDATE SET consecutive_failures = lockout_state.consecutive_failures + 1 RETURNING consecutive_failures`, [identity.id]);
    const failures = result.rows[0]?.consecutive_failures ?? 0;
    if (failures >= config.lockoutThreshold) {
      const lockedUntil = new Date(Date.now() + config.lockoutDurationSec * 1000);
      await this.db.query('UPDATE lockout_state SET locked_until = $1 WHERE identity_id = $2', [lockedUntil, identity.id]);
      await this.auditLogger.record({ type: 'auth.account_locked', identityId: identity.id, orgContext, detail: { failures, lockedUntil: lockedUntil.toISOString() } });
    }
  }

  private async resetFailures(identifier: string, orgContext: string): Promise<void> {
    const identity = await this.findIdentity(identifier, orgContext);
    if (!identity) return;
    await this.db.query('UPDATE lockout_state SET consecutive_failures = 0, locked_until = NULL WHERE identity_id = $1', [identity.id]);
  }

  private async findIdentity(identifier: string, orgContext: string): Promise<{ id: string; verification_status: string } | null> {
    const result = await this.db.query<{ id: string; verification_status: string }>('SELECT id, verification_status FROM identity WHERE identifier = $1 AND org_context = $2', [identifier, orgContext]);
    return result.rows[0] ?? null;
  }
}
