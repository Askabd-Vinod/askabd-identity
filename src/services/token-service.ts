import { randomUUID, createHash } from 'node:crypto';
import * as jose from 'jose';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result } from './identity-manager.js';

export interface TokenClaims {
  sub: string; org: string; sid: string; iat: number; exp: number; jti: string;
}

export interface TokenPair {
  accessToken: string; refreshToken: string; accessTokenId: string; refreshTokenId: string;
}

export type TokenValidation =
  | { valid: true; claims: TokenClaims }
  | { valid: false; reason: 'expired' | 'signature_invalid' | 'malformed' | 'revoked' };

let signingKey: jose.KeyLike | null = null;
let verifyKey: jose.KeyLike | null = null;

async function getKeys(): Promise<{ signing: jose.KeyLike; verify: jose.KeyLike }> {
  if (!signingKey || !verifyKey) {
    const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA');
    signingKey = privateKey; verifyKey = publicKey;
  }
  return { signing: signingKey, verify: verifyKey };
}

export function resetTokenKeys(): void { signingKey = null; verifyKey = null; }

export class TokenService {
  constructor(private readonly db: DbClient, private readonly auditLogger: AuditLogger, private readonly eventPublisher: EventPublisher) {}

  async issueForSession(sessionId: string, identityId: string, orgContext: string): Promise<TokenPair> {
    const config = getSecurityConfig();
    const keys = await getKeys();
    const accessTokenId = randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const exp = now + config.accessTokenLifetimeSec;
    const accessToken = await new jose.SignJWT({ sub: identityId, org: orgContext, sid: sessionId })
      .setProtectedHeader({ alg: 'EdDSA' }).setJti(accessTokenId).setIssuedAt(now).setExpirationTime(exp).setIssuer('askabd-identity').sign(keys.signing);
    await this.db.query('INSERT INTO access_token (id, session_id, issued_at, expires_at, revoked) VALUES ($1, $2, $3, $4, FALSE)', [accessTokenId, sessionId, new Date(now * 1000), new Date(exp * 1000)]);
    const refreshTokenId = randomUUID();
    const refreshTokenRaw = `rt_${randomUUID()}${randomUUID()}`.replace(/-/g, '');
    const refreshTokenHash = createHash('sha256').update(refreshTokenRaw).digest('hex');
    const refreshExp = new Date(Date.now() + config.refreshTokenLifetimeSec * 1000);
    await this.db.query('INSERT INTO refresh_token (id, session_id, token_hash, prev_token_id, expires_at, status) VALUES ($1, $2, $3, NULL, $4, \'active\')', [refreshTokenId, sessionId, refreshTokenHash, refreshExp]);
    return { accessToken, refreshToken: refreshTokenRaw, accessTokenId, refreshTokenId };
  }

  async validate(accessToken: string): Promise<TokenValidation> {
    const keys = await getKeys();
    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(accessToken, keys.verify, { issuer: 'askabd-identity' });
      payload = result.payload;
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) return { valid: false, reason: 'expired' };
      if (err instanceof jose.errors.JWSSignatureVerificationFailed) return { valid: false, reason: 'signature_invalid' };
      return { valid: false, reason: 'malformed' };
    }
    const jti = payload.jti;
    if (jti) {
      const result = await this.db.query<{ revoked: boolean }>('SELECT revoked FROM access_token WHERE id = $1', [jti]);
      if (result.rows.length > 0 && result.rows[0]!.revoked) return { valid: false, reason: 'revoked' };
    }
    return { valid: true, claims: { sub: payload.sub as string, org: (payload as any).org, sid: (payload as any).sid, iat: payload.iat as number, exp: payload.exp as number, jti: payload.jti as string } };
  }

  async refresh(refreshToken: string, sessionId: string): Promise<Result<TokenPair>> {
    const tokenHash = createHash('sha256').update(refreshToken).digest('hex');
    const result = await this.db.query<{ id: string; session_id: string; expires_at: Date; status: string }>('SELECT id, session_id, expires_at, status FROM refresh_token WHERE token_hash = $1', [tokenHash]);
    if (result.rows.length === 0) return { ok: false, error: { category: 'authentication', code: 'invalid_token', message: 'Refresh token is invalid' } };
    const row = result.rows[0]!;
    if (row.status === 'rotated') { await this.revokeSessionChain(row.session_id); return { ok: false, error: { category: 'authentication', code: 'token_reuse', message: 'Refresh token reuse detected' } }; }
    if (row.status === 'revoked') return { ok: false, error: { category: 'authentication', code: 'token_revoked', message: 'Refresh token has been revoked' } };
    if (new Date() > row.expires_at) return { ok: false, error: { category: 'expired', code: 'token_expired', message: 'Refresh token has expired' } };
    await this.db.query(`UPDATE refresh_token SET status = 'rotated' WHERE id = $1`, [row.id]);
    const sessionResult = await this.db.query<{ identity_id: string; org_context: string }>('SELECT identity_id, org_context FROM session WHERE id = $1', [row.session_id]);
    if (sessionResult.rows.length === 0) return { ok: false, error: { category: 'authentication', code: 'session_invalid', message: 'Session not found' } };
    const { identity_id, org_context } = sessionResult.rows[0]!;
    const config = getSecurityConfig(); const keys = await getKeys();
    const newAccessTokenId = randomUUID(); const now = Math.floor(Date.now() / 1000); const exp = now + config.accessTokenLifetimeSec;
    const newAccessToken = await new jose.SignJWT({ sub: identity_id, org: org_context, sid: row.session_id }).setProtectedHeader({ alg: 'EdDSA' }).setJti(newAccessTokenId).setIssuedAt(now).setExpirationTime(exp).setIssuer('askabd-identity').sign(keys.signing);
    await this.db.query('INSERT INTO access_token (id, session_id, issued_at, expires_at, revoked) VALUES ($1, $2, $3, $4, FALSE)', [newAccessTokenId, row.session_id, new Date(now * 1000), new Date(exp * 1000)]);
    const newRefreshId = randomUUID(); const newRefreshRaw = `rt_${randomUUID()}${randomUUID()}`.replace(/-/g, ''); const newRefreshHash = createHash('sha256').update(newRefreshRaw).digest('hex');
    const refreshExp = new Date(Date.now() + config.refreshTokenLifetimeSec * 1000);
    await this.db.query('INSERT INTO refresh_token (id, session_id, token_hash, prev_token_id, expires_at, status) VALUES ($1, $2, $3, $4, $5, \'active\')', [newRefreshId, row.session_id, newRefreshHash, row.id, refreshExp]);
    return { ok: true, value: { accessToken: newAccessToken, refreshToken: newRefreshRaw, accessTokenId: newAccessTokenId, refreshTokenId: newRefreshId } };
  }

  async revoke(tokenId: string, orgContext: string): Promise<Result<{ alreadyRevoked: boolean }>> {
    const accessResult = await this.db.query<{ id: string; revoked: boolean; session_id: string }>('SELECT id, revoked, session_id FROM access_token WHERE id = $1', [tokenId]);
    if (accessResult.rows.length > 0) {
      const row = accessResult.rows[0]!;
      if (row.revoked) return { ok: true, value: { alreadyRevoked: true } };
      await this.db.query('UPDATE access_token SET revoked = TRUE WHERE id = $1', [tokenId]);
      await this.auditLogger.record({ type: 'token.revoked', orgContext, detail: { tokenId, tokenType: 'access' } });
      await this.eventPublisher.publish('token.revoked', orgContext, { tokenId, tokenType: 'access' });
      return { ok: true, value: { alreadyRevoked: false } };
    }
    const refreshResult = await this.db.query<{ id: string; status: string }>('SELECT id, status FROM refresh_token WHERE id = $1', [tokenId]);
    if (refreshResult.rows.length > 0) {
      const row = refreshResult.rows[0]!;
      if (row.status === 'revoked') return { ok: true, value: { alreadyRevoked: true } };
      await this.db.query(`UPDATE refresh_token SET status = 'revoked' WHERE id = $1`, [tokenId]);
      await this.auditLogger.record({ type: 'token.revoked', orgContext, detail: { tokenId, tokenType: 'refresh' } });
      await this.eventPublisher.publish('token.revoked', orgContext, { tokenId, tokenType: 'refresh' });
      return { ok: true, value: { alreadyRevoked: false } };
    }
    return { ok: false, error: { category: 'not_found', code: 'token_not_found', message: 'Token not found' } };
  }

  private async revokeSessionChain(sessionId: string): Promise<void> {
    await this.db.query(`UPDATE refresh_token SET status = 'revoked' WHERE session_id = $1`, [sessionId]);
    await this.db.query('UPDATE access_token SET revoked = TRUE WHERE session_id = $1', [sessionId]);
  }
}
