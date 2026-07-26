import { randomUUID, randomBytes, createHmac } from 'node:crypto';
import { DbClient } from '../db/index.js';
import { getSecurityConfig } from '../config/security.js';
import { type Result } from './identity-manager.js';
import { type DomainEvent } from './event-publisher.js';

export interface WebhookRegistration { id: string; url: string; eventType: string; orgContext: string; }

interface DeliveryFailure { registrationId: string; eventId: string; url: string; error: string; attempts: number; failedAt: string; }

export class WebhookDispatcher {
  private failures: DeliveryFailure[] = [];
  constructor(private readonly db: DbClient) {}

  async register(input: { url: string; eventType: string; orgContext: string }): Promise<Result<WebhookRegistration>> {
    if (!input.url || !this.isValidUrl(input.url)) return { ok: false, error: { category: 'validation', code: 'invalid_url', field: 'url', message: 'A valid HTTPS URL is required' } };
    if (!input.eventType || input.eventType.length < 1) return { ok: false, error: { category: 'validation', code: 'invalid_event_type', field: 'eventType', message: 'Event type is required' } };
    if (!input.orgContext || input.orgContext.length < 1 || input.orgContext.length > 255) return { ok: false, error: { category: 'validation', code: 'org_context_length', field: 'orgContext', message: 'org_context must be 1..255 characters' } };
    const id = randomUUID();
    const signingSecret = randomBytes(32).toString('hex');
    await this.db.query('INSERT INTO webhook_registration (id, url, event_type, org_context, signing_secret_enc) VALUES ($1, $2, $3, $4, $5)', [id, input.url, input.eventType, input.orgContext, signingSecret]);
    return { ok: true, value: { id, url: input.url, eventType: input.eventType, orgContext: input.orgContext } };
  }

  async deliver(event: DomainEvent): Promise<void> {
    const registrations = await this.db.query<{ id: string; url: string; signing_secret_enc: string }>(
      'SELECT id, url, signing_secret_enc FROM webhook_registration WHERE event_type = $1 AND org_context = $2 AND active = TRUE', [event.type, event.orgContext]);
    for (const reg of registrations.rows) { await this.deliverToEndpoint(reg, event); }
  }

  getFailures(): ReadonlyArray<DeliveryFailure> { return this.failures; }

  static sign(secret: string, timestamp: number, body: string): string {
    return `v1=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
  }

  private async deliverToEndpoint(reg: { id: string; url: string; signing_secret_enc: string }, event: DomainEvent): Promise<void> {
    const config = getSecurityConfig();
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = WebhookDispatcher.sign(reg.signing_secret_enc, timestamp, body);
    let lastError = '';
    for (let attempt = 1; attempt <= config.retryMaxAttempts; attempt++) {
      try {
        const response = await fetch(reg.url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Identity-Event-Id': event.id, 'X-Identity-Signature-Timestamp': String(timestamp), 'X-Identity-Signature': signature }, body, signal: AbortSignal.timeout(10000) });
        if (response.ok) return;
        lastError = `HTTP ${response.status}`;
      } catch (err) { lastError = err instanceof Error ? err.message : String(err); }
      if (attempt < config.retryMaxAttempts) await new Promise((r) => setTimeout(r, config.retryBaseDelayMs * Math.pow(2, attempt - 1)));
    }
    this.failures.push({ registrationId: reg.id, eventId: event.id, url: reg.url, error: lastError, attempts: config.retryMaxAttempts, failedAt: new Date().toISOString() });
  }

  private isValidUrl(url: string): boolean { try { const p = new URL(url); return p.protocol === 'https:' || p.protocol === 'http:'; } catch { return false; } }
}
