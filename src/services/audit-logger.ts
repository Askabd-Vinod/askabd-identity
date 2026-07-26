import { randomUUID } from 'node:crypto';
import { DbClient } from '../db/index.js';

/**
 * Audit_Logger (R16)
 *
 * Append-only, immutable audit event recording.
 * - record(): creates an audit event with unique id, type, timestamp
 * - query(): retrieves events scoped to a tenant within a time range
 * - No update or delete methods exist by design (R16.3)
 */

export interface AuditEvent {
  id: string;
  type: string;
  identityId: string | null;
  orgContext: string | null;
  at: Date;
  detail: Record<string, unknown>;
}

export interface RecordAuditInput {
  type: string;
  identityId?: string;
  orgContext?: string;
  detail?: Record<string, unknown>;
}

export interface QueryAuditInput {
  orgContext: string;
  from: Date;
  to: Date;
  limit?: number;
  identityId?: string;
  type?: string;
}

export interface AuditQueryResult {
  events: AuditEvent[];
  count: number;
}

export class AuditLogger {
  constructor(private readonly db: DbClient) {}

  async record(input: RecordAuditInput): Promise<AuditEvent> {
    const id = randomUUID();
    const at = new Date();
    const detail = input.detail ?? {};

    const result = await this.db.query<{
      id: string; type: string; identity_id: string | null;
      org_context: string | null; at: Date; detail: Record<string, unknown>;
    }>(
      `INSERT INTO audit_event (id, type, identity_id, org_context, at, detail)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, type, identity_id, org_context, at, detail`,
      [id, input.type, input.identityId ?? null, input.orgContext ?? null, at, JSON.stringify(detail)],
    );

    const row = result.rows[0];
    if (!row) throw new Error('Failed to record audit event');

    return { id: row.id, type: row.type, identityId: row.identity_id, orgContext: row.org_context, at: row.at, detail: row.detail };
  }

  async query(input: QueryAuditInput): Promise<AuditQueryResult> {
    if (!input.orgContext || input.orgContext.length < 1 || input.orgContext.length > 255) {
      throw new AuditValidationError('orgContext', 'org_context must be 1..255 characters');
    }
    if (!input.from || !input.to) {
      throw new AuditValidationError('from/to', 'from and to dates are required');
    }
    if (input.to <= input.from) {
      throw new AuditValidationError('to', 'to must be after from');
    }

    const limit = Math.min(input.limit ?? 100, 1000);
    const params: unknown[] = [input.orgContext, input.from, input.to];
    let whereClause = 'WHERE org_context = $1 AND at >= $2 AND at <= $3';
    let paramIndex = 4;

    if (input.identityId) {
      whereClause += ` AND identity_id = $${paramIndex}`;
      params.push(input.identityId);
      paramIndex++;
    }
    if (input.type) {
      whereClause += ` AND type = $${paramIndex}`;
      params.push(input.type);
      paramIndex++;
    }

    params.push(limit);

    const result = await this.db.query<{
      id: string; type: string; identity_id: string | null;
      org_context: string | null; at: Date; detail: Record<string, unknown>;
    }>(
      `SELECT id, type, identity_id, org_context, at, detail FROM audit_event ${whereClause} ORDER BY at ASC LIMIT $${paramIndex}`,
      params,
    );

    const events: AuditEvent[] = result.rows.map((row) => ({
      id: row.id, type: row.type, identityId: row.identity_id,
      orgContext: row.org_context, at: row.at, detail: row.detail,
    }));

    return { events, count: events.length };
  }
}

export class AuditValidationError extends Error {
  public readonly field: string;
  constructor(field: string, message: string) {
    super(message);
    this.name = 'AuditValidationError';
    this.field = field;
  }
}
