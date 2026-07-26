import { randomUUID } from 'node:crypto';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result } from './identity-manager.js';

export interface Session {
  id: string;
  identityId: string;
  orgContext: string;
  clientMeta: Record<string, unknown>;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  status: 'active' | 'terminated' | 'expired';
}

export interface CreateSessionInput {
  identityId: string;
  orgContext: string;
  clientMeta?: Record<string, unknown>;
}

export type SessionValidation =
  | { valid: true; session: Session }
  | { valid: false; reason: 'expired' | 'terminated' | 'not_found' };

export class SessionManager {
  constructor(
    private readonly db: DbClient,
    private readonly auditLogger: AuditLogger,
    private readonly eventPublisher: EventPublisher,
  ) {}

  async create(input: CreateSessionInput): Promise<Session> {
    const config = getSecurityConfig();
    const now = new Date();
    const id = randomUUID();
    const idleExpiresAt = new Date(now.getTime() + config.sessionIdleTimeoutSec * 1000);
    const absoluteExpiresAt = new Date(now.getTime() + config.sessionAbsoluteTimeoutSec * 1000);

    await this.evictExcessSessions(input.identityId, input.orgContext, config.maxConcurrentSessions - 1);

    const result = await this.db.query<any>(
      `INSERT INTO session (id, identity_id, org_context, client_meta, created_at, last_seen_at, idle_expires_at, absolute_expires_at, status) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, 'active') RETURNING *`,
      [id, input.identityId, input.orgContext, JSON.stringify(input.clientMeta ?? {}), now, idleExpiresAt, absoluteExpiresAt],
    );
    const session = this.mapRow(result.rows[0]!);

    await this.auditLogger.record({ type: 'session.started', identityId: input.identityId, orgContext: input.orgContext, detail: { sessionId: id } });
    await this.eventPublisher.publish('session.started', input.orgContext, { sessionId: id, identityId: input.identityId });
    return session;
  }

  async validate(sessionId: string): Promise<SessionValidation> {
    const result = await this.db.query<any>('SELECT * FROM session WHERE id = $1', [sessionId]);
    if (result.rows.length === 0) return { valid: false, reason: 'not_found' };
    const session = this.mapRow(result.rows[0]!);
    if (session.status === 'terminated') return { valid: false, reason: 'terminated' };
    const now = new Date();
    if (now > session.absoluteExpiresAt || now > session.idleExpiresAt) {
      await this.db.query(`UPDATE session SET status = 'expired' WHERE id = $1`, [sessionId]);
      return { valid: false, reason: 'expired' };
    }
    const config = getSecurityConfig();
    const newIdleExpiry = new Date(now.getTime() + config.sessionIdleTimeoutSec * 1000);
    await this.db.query('UPDATE session SET last_seen_at = $1, idle_expires_at = $2 WHERE id = $3', [now, newIdleExpiry, sessionId]);
    return { valid: true, session: { ...session, lastSeenAt: now, idleExpiresAt: newIdleExpiry } };
  }

  async list(identityId: string, orgContext: string): Promise<Session[]> {
    const result = await this.db.query<any>(`SELECT * FROM session WHERE identity_id = $1 AND org_context = $2 AND status = 'active' ORDER BY created_at DESC`, [identityId, orgContext]);
    return result.rows.map((r: any) => this.mapRow(r));
  }

  async terminate(sessionId: string): Promise<Result<void>> {
    const result = await this.db.query<any>('SELECT id, identity_id, org_context, status FROM session WHERE id = $1', [sessionId]);
    if (result.rows.length === 0) return { ok: false, error: { category: 'not_found', code: 'session_not_found', message: 'Session not found' } };
    const row = result.rows[0]!;
    if (row.status === 'terminated') return { ok: true, value: undefined };
    await this.db.query(`UPDATE session SET status = 'terminated' WHERE id = $1`, [sessionId]);
    await this.auditLogger.record({ type: 'session.ended', identityId: row.identity_id, orgContext: row.org_context, detail: { sessionId } });
    await this.eventPublisher.publish('session.ended', row.org_context, { sessionId, identityId: row.identity_id });
    return { ok: true, value: undefined };
  }

  async terminateAllExcept(identityId: string, keepSessionId?: string): Promise<void> {
    if (keepSessionId) {
      await this.db.query(`UPDATE session SET status = 'terminated' WHERE identity_id = $1 AND id != $2 AND status = 'active'`, [identityId, keepSessionId]);
    } else {
      await this.db.query(`UPDATE session SET status = 'terminated' WHERE identity_id = $1 AND status = 'active'`, [identityId]);
    }
  }

  private async evictExcessSessions(identityId: string, orgContext: string, maxAllowed: number): Promise<void> {
    const active = await this.db.query<{ id: string }>(`SELECT id FROM session WHERE identity_id = $1 AND org_context = $2 AND status = 'active' ORDER BY created_at ASC`, [identityId, orgContext]);
    const excess = active.rows.length - maxAllowed;
    if (excess > 0) { for (let i = 0; i < excess; i++) { await this.terminate(active.rows[i]!.id); } }
  }

  private mapRow(row: any): Session {
    return { id: row.id, identityId: row.identity_id, orgContext: row.org_context, clientMeta: row.client_meta, createdAt: row.created_at, lastSeenAt: row.last_seen_at, idleExpiresAt: row.idle_expires_at, absoluteExpiresAt: row.absolute_expires_at, status: row.status };
  }
}
