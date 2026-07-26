import { randomUUID } from 'node:crypto';
import { getSecurityConfig } from '../config/security.js';

/**
 * Event_Publisher (R18)
 *
 * Emits domain events for all state changes.
 * - Globally unique IDs (R18.1)
 * - type, org_context, UTC timestamp (R18.1)
 * - NEVER includes credential or token secret values (R18.3)
 * - Retry with exponential backoff (R18.4)
 * - Dead-letter on exhaustion (R18.5)
 */

export interface DomainEvent {
  id: string;
  type: string;
  orgContext: string | null;
  time: string;
  data: Record<string, unknown>;
}

export type EventHandler = (event: DomainEvent) => Promise<void>;

interface DeadLetterEntry {
  event: DomainEvent;
  error: string;
  attempts: number;
  failedAt: string;
}

const FORBIDDEN_FIELDS = new Set([
  'password', 'credential', 'secret', 'hash', 'token',
  'refreshToken', 'accessToken', 'apiKey', 'privateKey',
  'signing_secret', 'secret_enc', 'token_hash',
]);

export class EventPublisher {
  private handlers: EventHandler[] = [];
  private deadLetterStore: DeadLetterEntry[] = [];
  private maxAttempts: number;
  private baseDelayMs: number;

  constructor(options?: { maxAttempts?: number; baseDelayMs?: number }) {
    this.maxAttempts = options?.maxAttempts ?? getSecurityConfig().retryMaxAttempts;
    this.baseDelayMs = options?.baseDelayMs ?? getSecurityConfig().retryBaseDelayMs;
  }

  subscribe(handler: EventHandler): void {
    this.handlers.push(handler);
  }

  async publish(type: string, orgContext: string | null, data: Record<string, unknown>): Promise<DomainEvent> {
    const event: DomainEvent = {
      id: `evt_${randomUUID()}`,
      type,
      orgContext,
      time: new Date().toISOString(),
      data: this.sanitizeData(data),
    };

    for (const handler of this.handlers) {
      await this.deliverWithRetry(event, handler);
    }

    return event;
  }

  getDeadLetters(): ReadonlyArray<DeadLetterEntry> {
    return this.deadLetterStore;
  }

  clearDeadLetters(): void {
    this.deadLetterStore = [];
  }

  private async deliverWithRetry(event: DomainEvent, handler: EventHandler): Promise<void> {
    const maxAttempts = this.maxAttempts;
    const baseDelay = this.baseDelayMs;

    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await handler(event);
        return;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < maxAttempts) {
          const delay = baseDelay * Math.pow(2, attempt - 1);
          await this.sleep(delay);
        }
      }
    }

    this.deadLetterStore.push({
      event,
      error: lastError?.message ?? 'Unknown error',
      attempts: maxAttempts,
      failedAt: new Date().toISOString(),
    });
  }

  private sanitizeData(data: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (FORBIDDEN_FIELDS.has(key) || FORBIDDEN_FIELDS.has(key.toLowerCase())) continue;
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        sanitized[key] = this.sanitizeData(value as Record<string, unknown>);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

let _publisher: EventPublisher | null = null;

export function getEventPublisher(): EventPublisher {
  if (!_publisher) _publisher = new EventPublisher();
  return _publisher;
}

export function resetEventPublisher(): void {
  _publisher = null;
}
