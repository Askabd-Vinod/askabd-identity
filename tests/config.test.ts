import { describe, it, expect } from 'vitest';
import { config } from '../src/config/env.js';

describe('Config', () => {
  it('loads with valid defaults', () => {
    expect(config.PORT).toBeGreaterThan(0);
    expect(config.PORT).toBeLessThanOrEqual(65535);
    expect(config.HOST).toBeDefined();
    expect(config.VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(config.LOG_LEVEL).toBeDefined();
  });

  it('has a valid NODE_ENV', () => {
    expect(['development', 'production', 'test']).toContain(config.NODE_ENV);
  });
});
