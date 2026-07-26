import { DbClient } from './connection.js';

/**
 * Base repository that enforces tenant isolation (R21).
 * Every query is scoped to a single org_context.
 * org_context is treated as untrusted external input and always parameterized.
 */
export abstract class TenantScopedRepository {
  constructor(
    protected readonly db: DbClient,
    protected readonly orgContext: string,
  ) {
    if (!orgContext || orgContext.length < 1 || orgContext.length > 255) {
      throw new Error('org_context must be 1..255 characters');
    }
  }

  /**
   * Execute a query scoped to this tenant.
   * Automatically injects org_context as the last parameter.
   */
  protected async scopedQuery<T extends Record<string, unknown>>(
    text: string,
    params: unknown[] = [],
  ): Promise<T[]> {
    const result = await this.db.query<T>(text, [...params, this.orgContext]);
    return result.rows;
  }

  /**
   * Execute a query scoped to this tenant, returning a single row or null.
   */
  protected async scopedQueryOne<T extends Record<string, unknown>>(
    text: string,
    params: unknown[] = [],
  ): Promise<T | null> {
    const rows = await this.scopedQuery<T>(text, params);
    return rows[0] ?? null;
  }

  /**
   * Execute a non-scoped query (for cross-cutting concerns like audit).
   */
  protected async query<T extends Record<string, unknown>>(
    text: string,
    params: unknown[] = [],
  ): Promise<T[]> {
    const result = await this.db.query<T>(text, params);
    return result.rows;
  }
}
