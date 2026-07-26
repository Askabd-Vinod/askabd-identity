import { randomUUID, randomBytes, createHmac } from 'node:crypto';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result } from './identity-manager.js';

export interface MfaEnrollment { methodId: string; secret: string; provisioningUri: string; }

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buffer: Buffer): string { let bits = 0; let value = 0; let output = ''; for (const byte of buffer) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { output += BASE32_CHARS[(value >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) output += BASE32_CHARS[(value << (5 - bits)) & 31]; return output; }
export function base32Decode(encoded: string): Buffer { const clean = encoded.replace(/=+$/, '').toUpperCase(); const bytes: number[] = []; let bits = 0; let value = 0; for (const char of clean) { const idx = BASE32_CHARS.indexOf(char); if (idx === -1) continue; value = (value << 5) | idx; bits += 5; if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; } } return Buffer.from(bytes); }

export class MfaService {
  constructor(private readonly db: DbClient, private readonly auditLogger: AuditLogger, private readonly eventPublisher: EventPublisher) {}

  async enroll(identityId: string, orgContext: string, accountName?: string): Promise<Result<MfaEnrollment>> {
    const existing = await this.db.query<{ id: string }>(`SELECT id, status FROM mfa_method WHERE identity_id = $1 AND status IN ('active', 'pending')`, [identityId]);
    if (existing.rows.length > 0) return { ok: false, error: { category: 'conflict', code: 'mfa_already_exists', message: 'An MFA method is already enrolled or pending' } };
    const secretBytes = randomBytes(20);
    const secret = base32Encode(secretBytes);
    const methodId = randomUUID();
    await this.db.query(`INSERT INTO mfa_method (id, identity_id, type, secret_enc, status) VALUES ($1, $2, 'totp', $3, 'pending')`, [methodId, identityId, secret]);
    const issuer = 'AskABD'; const account = accountName ?? identityId;
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    await this.auditLogger.record({ type: 'mfa.enrolled', identityId, orgContext, detail: { methodId, type: 'totp' } });
    return { ok: true, value: { methodId, secret, provisioningUri } };
  }

  async activate(identityId: string, code: string, orgContext: string): Promise<Result<void>> {
    const method = await this.getPendingMethod(identityId);
    if (!method) return { ok: false, error: { category: 'not_found', code: 'no_pending_mfa', message: 'No pending MFA method found' } };
    if (!this.verifyTotp(method.secret_enc, code)) return { ok: false, error: { category: 'authentication', code: 'invalid_mfa_code', message: 'Invalid MFA code' } };
    await this.db.query(`UPDATE mfa_method SET status = 'active' WHERE id = $1`, [method.id]);
    await this.auditLogger.record({ type: 'mfa.activated', identityId, orgContext, detail: { methodId: method.id } });
    await this.eventPublisher.publish('mfa.activated', orgContext, { identityId, methodId: method.id });
    return { ok: true, value: undefined };
  }

  async challenge(identityId: string, code: string): Promise<Result<{ granted: true }>> {
    const method = await this.getActiveMethod(identityId);
    if (!method) return { ok: false, error: { category: 'not_found', code: 'no_active_mfa', message: 'No active MFA method found' } };
    if (!this.verifyTotp(method.secret_enc, code)) return { ok: false, error: { category: 'authentication', code: 'invalid_mfa_code', message: 'Invalid MFA code' } };
    return { ok: true, value: { granted: true } };
  }

  async disable(identityId: string, code: string, orgContext: string): Promise<Result<void>> {
    const method = await this.getActiveMethod(identityId);
    if (!method) return { ok: false, error: { category: 'not_found', code: 'no_active_mfa', message: 'No active MFA method found' } };
    if (!this.verifyTotp(method.secret_enc, code)) return { ok: false, error: { category: 'authentication', code: 'invalid_mfa_code', message: 'Invalid MFA code — method remains active' } };
    await this.db.query(`UPDATE mfa_method SET status = 'disabled' WHERE id = $1`, [method.id]);
    await this.auditLogger.record({ type: 'mfa.disabled', identityId, orgContext, detail: { methodId: method.id } });
    await this.eventPublisher.publish('mfa.disabled', orgContext, { identityId, methodId: method.id });
    return { ok: true, value: undefined };
  }

  async isActive(identityId: string): Promise<boolean> { return (await this.getActiveMethod(identityId)) !== null; }

  private async getPendingMethod(identityId: string) {
    const r = await this.db.query<{ id: string; secret_enc: string }>(`SELECT id, secret_enc FROM mfa_method WHERE identity_id = $1 AND status = 'pending' LIMIT 1`, [identityId]);
    return r.rows[0] ?? null;
  }
  private async getActiveMethod(identityId: string) {
    const r = await this.db.query<{ id: string; secret_enc: string }>(`SELECT id, secret_enc FROM mfa_method WHERE identity_id = $1 AND status = 'active' LIMIT 1`, [identityId]);
    return r.rows[0] ?? null;
  }

  private verifyTotp(secret: string, code: string): boolean {
    if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) return false;
    const config = getSecurityConfig();
    const now = Math.floor(Date.now() / 1000);
    const currentStep = Math.floor(now / config.totpPeriodSec);
    for (let i = -config.totpDriftSteps; i <= config.totpDriftSteps; i++) {
      if (this.generateTotp(secret, currentStep + i) === code) return true;
    }
    return false;
  }

  private generateTotp(secret: string, step: number): string {
    const secretBytes = base32Decode(secret);
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigUInt64BE(BigInt(step));
    const hmac = createHmac('sha1', secretBytes).update(timeBuffer).digest();
    const offset = hmac[hmac.length - 1]! & 0x0f;
    const binary = ((hmac[offset]! & 0x7f) << 24) | ((hmac[offset + 1]! & 0xff) << 16) | ((hmac[offset + 2]! & 0xff) << 8) | (hmac[offset + 3]! & 0xff);
    return (binary % 1_000_000).toString().padStart(6, '0');
  }
}
