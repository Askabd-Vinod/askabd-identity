import { randomUUID } from 'node:crypto';
import { DbClient } from '../db/index.js';
import { AuditLogger } from './audit-logger.js';
import { EventPublisher } from './event-publisher.js';
import { type Result } from './identity-manager.js';

export interface Role { id: string; name: string; orgContext: string; permissions: string[]; }

export class AuthorizationService {
  constructor(private readonly db: DbClient, private readonly auditLogger: AuditLogger, private readonly eventPublisher: EventPublisher) {}

  async createRole(input: { name: string; orgContext: string; permissions: string[] }): Promise<Result<{ roleId: string }>> {
    if (!input.name || input.name.length < 1 || input.name.length > 255) return { ok: false, error: { category: 'validation', code: 'role_name_length', field: 'name', message: 'Role name must be 1..255 characters' } };
    if (!input.orgContext || input.orgContext.length < 1 || input.orgContext.length > 255) return { ok: false, error: { category: 'validation', code: 'org_context_length', field: 'orgContext', message: 'org_context must be 1..255 characters' } };
    if (!input.permissions || input.permissions.length === 0) return { ok: false, error: { category: 'validation', code: 'permissions_empty', field: 'permissions', message: 'Permissions must not be empty' } };
    const existing = await this.db.query<{ id: string }>('SELECT id FROM role WHERE org_context = $1 AND name = $2', [input.orgContext, input.name]);
    if (existing.rows.length > 0) return { ok: false, error: { category: 'conflict', code: 'role_exists', field: 'name', message: 'A role with this name already exists' } };
    const roleId = randomUUID();
    await this.db.query('INSERT INTO role (id, name, org_context) VALUES ($1, $2, $3)', [roleId, input.name, input.orgContext]);
    for (const perm of input.permissions) {
      const [action, resourceType] = perm.split(':');
      if (!action || !resourceType) continue;
      const permId = randomUUID();
      await this.db.query('INSERT INTO permission (id, action, resource_type, org_context) VALUES ($1, $2, $3, $4) ON CONFLICT (org_context, action, resource_type) DO NOTHING', [permId, action, resourceType, input.orgContext]);
      const permResult = await this.db.query<{ id: string }>('SELECT id FROM permission WHERE org_context = $1 AND action = $2 AND resource_type = $3', [input.orgContext, action, resourceType]);
      if (permResult.rows[0]) await this.db.query('INSERT INTO role_permission (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roleId, permResult.rows[0].id]);
    }
    await this.auditLogger.record({ type: 'role.created', orgContext: input.orgContext, detail: { roleId, name: input.name, permissions: input.permissions } });
    return { ok: true, value: { roleId } };
  }

  async assignRole(input: { identityId: string; roleId: string; orgContext: string }): Promise<Result<void>> {
    const role = await this.db.query<{ id: string }>('SELECT id FROM role WHERE id = $1 AND org_context = $2', [input.roleId, input.orgContext]);
    if (role.rows.length === 0) return { ok: false, error: { category: 'not_found', code: 'role_not_found', message: 'Role not found' } };
    const identity = await this.db.query<{ id: string }>('SELECT id FROM identity WHERE id = $1 AND org_context = $2', [input.identityId, input.orgContext]);
    if (identity.rows.length === 0) return { ok: false, error: { category: 'not_found', code: 'identity_not_found', message: 'Identity not found' } };
    await this.db.query('INSERT INTO role_assignment (identity_id, role_id, org_context) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [input.identityId, input.roleId, input.orgContext]);
    await this.auditLogger.record({ type: 'role.assigned', identityId: input.identityId, orgContext: input.orgContext, detail: { roleId: input.roleId } });
    return { ok: true, value: undefined };
  }

  async revokeRole(input: { identityId: string; roleId: string; orgContext: string }): Promise<Result<void>> {
    const role = await this.db.query<{ id: string }>('SELECT id FROM role WHERE id = $1 AND org_context = $2', [input.roleId, input.orgContext]);
    if (role.rows.length === 0) return { ok: false, error: { category: 'not_found', code: 'role_not_found', message: 'Role not found' } };
    await this.db.query('DELETE FROM role_assignment WHERE identity_id = $1 AND role_id = $2 AND org_context = $3', [input.identityId, input.roleId, input.orgContext]);
    await this.auditLogger.record({ type: 'role.revoked', identityId: input.identityId, orgContext: input.orgContext, detail: { roleId: input.roleId } });
    return { ok: true, value: undefined };
  }

  async check(input: { identityId: string; action: string; resourceType: string; orgContext: string }): Promise<Result<{ decision: 'allow' | 'deny' }>> {
    if (!input.identityId) return { ok: false, error: { category: 'validation', code: 'missing_field', field: 'identityId', message: 'identityId is required' } };
    if (!input.action) return { ok: false, error: { category: 'validation', code: 'missing_field', field: 'action', message: 'action is required' } };
    if (!input.resourceType) return { ok: false, error: { category: 'validation', code: 'missing_field', field: 'resourceType', message: 'resourceType is required' } };
    if (!input.orgContext) return { ok: false, error: { category: 'validation', code: 'missing_field', field: 'orgContext', message: 'orgContext is required' } };
    const identity = await this.db.query<{ id: string }>('SELECT id FROM identity WHERE id = $1 AND org_context = $2', [input.identityId, input.orgContext]);
    if (identity.rows.length === 0) return { ok: true, value: { decision: 'deny' } };
    const permissions = await this.db.query<{ action: string; resource_type: string }>(
      'SELECT DISTINCT p.action, p.resource_type FROM role_assignment ra JOIN role_permission rp ON rp.role_id = ra.role_id JOIN permission p ON p.id = rp.permission_id WHERE ra.identity_id = $1 AND ra.org_context = $2 AND p.org_context = $2',
      [input.identityId, input.orgContext]);
    const hasPermission = permissions.rows.some((p) => p.action === input.action && p.resource_type === input.resourceType);
    return { ok: true, value: { decision: hasPermission ? 'allow' : 'deny' } };
  }
}
