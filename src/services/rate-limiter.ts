import { getSecurityConfig } from '../config/security.js';

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs?: number;
  remaining?: number;
}

interface BucketEntry {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private buckets: Map<string, BucketEntry> = new Map();
  private threshold: number;
  private windowMs: number;

  constructor(options?: { threshold?: number; windowSec?: number }) {
    const config = getSecurityConfig();
    this.threshold = options?.threshold ?? config.rateLimitDefaultThreshold;
    this.windowMs = (options?.windowSec ?? config.rateLimitDefaultWindowSec) * 1000;
    if (this.threshold < 1) this.threshold = 1;
    if (this.windowMs < 1000) this.windowMs = 1000;
  }

  check(clientId: string): RateLimitResult {
    const now = Date.now();
    const entry = this.buckets.get(clientId);
    if (!entry || (now - entry.windowStart) >= this.windowMs) {
      this.buckets.set(clientId, { count: 1, windowStart: now });
      return { allowed: true, remaining: this.threshold - 1 };
    }
    if (entry.count >= this.threshold) {
      const retryAfterMs = this.windowMs - (now - entry.windowStart);
      return { allowed: false, retryAfterMs: Math.max(retryAfterMs, 0) };
    }
    entry.count++;
    return { allowed: true, remaining: this.threshold - entry.count };
  }

  reset(clientId: string): void { this.buckets.delete(clientId); }
  getCount(clientId: string): number {
    const entry = this.buckets.get(clientId);
    if (!entry) return 0;
    if (Date.now() - entry.windowStart >= this.windowMs) return 0;
    return entry.count;
  }
}
