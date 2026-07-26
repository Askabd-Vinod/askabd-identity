/**
 * Identity_SDK (R20)
 * Typed client for the AskABD Identity Platform.
 */

export const SDK_VERSION = '0.1.0';
export const TARGET_API_VERSION = 'v1';

export type SdkErrorCategory = 'validation' | 'authentication' | 'authorization' | 'conflict' | 'not_found' | 'rate_limited' | 'server' | 'transport' | 'version_mismatch';

export interface SdkError { category: SdkErrorCategory; code: string; field?: string; message: string; retryAfterMs?: number; }
export type SdkResult<T> = { ok: true; value: T } | { ok: false; error: SdkError };

export interface LoginRequest { identifier: string; credential: string; orgContext: string; mfaCode?: string; }
export interface LoginSuccess { type: 'success'; accessToken: string; refreshToken: string; sessionId: string; }
export interface MfaRequired { type: 'mfa_required'; challengeId: string; }
export type LoginResult = LoginSuccess | MfaRequired;
export interface TokenClaims { sub: string; org: string; sid: string; iat: number; exp: number; jti: string; }
export interface TokenPair { accessToken: string; refreshToken: string; }
export interface PolicyCheckRequest { identityId: string; action: string; resourceType: string; orgContext: string; }
export interface PolicyDecision { decision: 'allow' | 'deny'; }
export interface IdentitySdkConfig { baseUrl: string; timeoutMs?: number; }

export class IdentitySdk {
  readonly targetApiVersion = TARGET_API_VERSION;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(config: IdentitySdkConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.timeoutMs = config.timeoutMs ?? 10_000;
  }

  async authenticate(req: LoginRequest): Promise<SdkResult<LoginResult>> {
    return this.post<LoginResult>('/auth/login', { identifier: req.identifier, credential: req.credential, mfaCode: req.mfaCode }, req.orgContext);
  }

  async validateToken(accessToken: string): Promise<SdkResult<{ valid: true; claims: TokenClaims } | { valid: false; reason: string }>> {
    return this.post('/tokens/validate', { accessToken });
  }

  async refresh(refreshToken: string, sessionId: string): Promise<SdkResult<TokenPair>> {
    return this.post<TokenPair>('/tokens/refresh', { refreshToken, sessionId });
  }

  async terminateSession(sessionId: string, orgContext: string): Promise<SdkResult<void>> {
    return this.post('/auth/logout', { sessionId }, orgContext);
  }

  async policyCheck(req: PolicyCheckRequest): Promise<SdkResult<PolicyDecision>> {
    return this.post<PolicyDecision>('/policy/check', { identityId: req.identityId, action: req.action, resourceType: req.resourceType }, req.orgContext);
  }

  private async post<T>(path: string, body: Record<string, unknown>, orgContext?: string): Promise<SdkResult<T>> {
    const url = `${this.baseUrl}/${this.targetApiVersion}${path}`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (orgContext) headers['X-Org-Context'] = orgContext;
    try {
      const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
      if (response.ok) {
        if (response.status === 204) return { ok: true, value: undefined as unknown as T };
        return { ok: true, value: await response.json() as T };
      }
      const errorBody = await response.json().catch(() => null) as any;
      if (errorBody?.error) {
        return { ok: false, error: { category: this.mapCategory(errorBody.error.category), code: errorBody.error.code ?? 'unknown', field: errorBody.error.field, message: errorBody.error.message ?? 'Request failed', retryAfterMs: errorBody.error.retryAfterMs } };
      }
      return { ok: false, error: { category: 'server', code: `http_${response.status}`, message: `HTTP ${response.status}` } };
    } catch (err) {
      if (err instanceof DOMException && err.name === 'TimeoutError') return { ok: false, error: { category: 'transport', code: 'timeout', message: 'Request timed out' } };
      return { ok: false, error: { category: 'transport', code: 'unknown', message: err instanceof Error ? err.message : 'Unknown error' } };
    }
  }

  private mapCategory(raw?: string): SdkErrorCategory {
    const valid: SdkErrorCategory[] = ['validation', 'authentication', 'authorization', 'conflict', 'not_found', 'rate_limited', 'server'];
    if (raw && valid.includes(raw as SdkErrorCategory)) return raw as SdkErrorCategory;
    return 'server';
  }
}
