import { describe, it, expect } from 'vitest';
import { loadSecurityConfig, BASELINE } from '../src/config/security.js';

describe('SecurityConfig', () => {
  describe('defaults', () => {
    it('loads valid defaults with no overrides', () => {
      const config = loadSecurityConfig({});
      expect(config.accessTokenLifetimeSec).toBe(900);
      expect(config.refreshTokenLifetimeSec).toBe(604_800);
      expect(config.totpDigits).toBe(6);
      expect(config.totpPeriodSec).toBe(30);
      expect(config.totpDriftSteps).toBe(1);
      expect(config.lockoutThreshold).toBe(10);
      expect(config.lockoutDurationSec).toBe(900);
      expect(config.sessionIdleTimeoutSec).toBe(1800);
      expect(config.sessionAbsoluteTimeoutSec).toBe(43_200);
      expect(config.credentialMinLength).toBe(8);
      expect(config.credentialMaxAcceptLength).toBe(128);
      expect(config.credentialRequireBreachCheck).toBe(true);
    });
  });

  describe('clamping — values within bounds', () => {
    it('accepts access token lifetime within range', () => {
      const config = loadSecurityConfig({ accessTokenLifetimeSec: 300 });
      expect(config.accessTokenLifetimeSec).toBe(300);
    });

    it('accepts refresh token lifetime within range', () => {
      const config = loadSecurityConfig({ refreshTokenLifetimeSec: 86_400 });
      expect(config.refreshTokenLifetimeSec).toBe(86_400);
    });

    it('accepts lockout threshold within range', () => {
      const config = loadSecurityConfig({ lockoutThreshold: 5 });
      expect(config.lockoutThreshold).toBe(5);
    });

    it('accepts session idle timeout within range', () => {
      const config = loadSecurityConfig({ sessionIdleTimeoutSec: 600 });
      expect(config.sessionIdleTimeoutSec).toBe(600);
    });

    it('accepts session absolute timeout within range', () => {
      const config = loadSecurityConfig({ sessionAbsoluteTimeoutSec: 3600 });
      expect(config.sessionAbsoluteTimeoutSec).toBe(3600);
    });
  });

  describe('fail-fast — values exceeding ceilings', () => {
    it('rejects access token lifetime exceeding 15 minutes', () => {
      expect(() =>
        loadSecurityConfig({ accessTokenLifetimeSec: 901 }),
      ).toThrow(/access.*token.*lifetime.*must not exceed.*900/i);
    });

    it('rejects refresh token lifetime exceeding 30 days', () => {
      expect(() =>
        loadSecurityConfig({ refreshTokenLifetimeSec: 2_592_001 }),
      ).toThrow(/refresh.*token.*lifetime.*must not exceed/i);
    });

    it('rejects lockout threshold exceeding 100', () => {
      expect(() =>
        loadSecurityConfig({ lockoutThreshold: 101 }),
      ).toThrow(/lockout.*threshold.*must not exceed.*100/i);
    });

    it('rejects session idle timeout exceeding 30 minutes', () => {
      expect(() =>
        loadSecurityConfig({ sessionIdleTimeoutSec: 1801 }),
      ).toThrow(/session.*idle.*must not exceed.*1800/i);
    });

    it('rejects session absolute timeout exceeding 12 hours', () => {
      expect(() =>
        loadSecurityConfig({ sessionAbsoluteTimeoutSec: 43_201 }),
      ).toThrow(/session.*absolute.*must not exceed.*43200/i);
    });
  });

  describe('fail-fast — values below floors', () => {
    it('rejects lockout duration below 15 minutes', () => {
      expect(() =>
        loadSecurityConfig({ lockoutDurationSec: 899 }),
      ).toThrow(/lockout.*duration.*must be at least.*900/i);
    });

    it('rejects credential min length below 8', () => {
      expect(() =>
        loadSecurityConfig({ credentialMinLength: 7 }),
      ).toThrow(/credential.*minimum.*length.*must be at least.*8/i);
    });

    it('rejects credential max accept length below 64', () => {
      expect(() =>
        loadSecurityConfig({ credentialMaxAcceptLength: 63 }),
      ).toThrow(/must accept.*at least.*64/i);
    });

    it('rejects retry attempts below 3', () => {
      expect(() =>
        loadSecurityConfig({ retryMaxAttempts: 2 }),
      ).toThrow(/retry.*must be at least.*3/i);
    });

    it('rejects retry attempts above 10', () => {
      expect(() =>
        loadSecurityConfig({ retryMaxAttempts: 11 }),
      ).toThrow(/retry.*must not exceed.*10/i);
    });

    it('rejects argon2 memory cost below 64 MB', () => {
      expect(() =>
        loadSecurityConfig({ argon2MemoryCostKb: 32_768 }),
      ).toThrow(/argon2.*memory.*must be at least/i);
    });

    it('rejects argon2 time cost below 3', () => {
      expect(() =>
        loadSecurityConfig({ argon2TimeCost: 2 }),
      ).toThrow(/argon2.*time.*must be at least.*3/i);
    });

    it('rejects access token lifetime below 60 seconds', () => {
      expect(() =>
        loadSecurityConfig({ accessTokenLifetimeSec: 59 }),
      ).toThrow(/access.*token.*lifetime.*must be at least.*60/i);
    });

    it('rejects rate limit threshold below 1', () => {
      expect(() =>
        loadSecurityConfig({ rateLimitDefaultThreshold: 0 }),
      ).toThrow();
    });

    it('rejects rate limit window below 1 second', () => {
      expect(() =>
        loadSecurityConfig({ rateLimitDefaultWindowSec: 0 }),
      ).toThrow();
    });
  });

  describe('TOTP fixed parameters', () => {
    it('TOTP digits is always 6', () => {
      const config = loadSecurityConfig({});
      expect(config.totpDigits).toBe(6);
    });

    it('TOTP period is always 30s', () => {
      const config = loadSecurityConfig({});
      expect(config.totpPeriodSec).toBe(30);
    });

    it('TOTP drift is always ±1 step', () => {
      const config = loadSecurityConfig({});
      expect(config.totpDriftSteps).toBe(1);
    });
  });

  describe('baseline constants', () => {
    it('exports correct baseline values', () => {
      expect(BASELINE.ACCESS_TOKEN_MAX_LIFETIME_SEC).toBe(900);
      expect(BASELINE.REFRESH_TOKEN_MAX_LIFETIME_SEC).toBe(2_592_000);
      expect(BASELINE.TOTP_DIGITS).toBe(6);
      expect(BASELINE.TOTP_PERIOD_SEC).toBe(30);
      expect(BASELINE.TOTP_DRIFT_STEPS).toBe(1);
      expect(BASELINE.LOCKOUT_MAX_THRESHOLD).toBe(100);
      expect(BASELINE.LOCKOUT_DEFAULT_THRESHOLD).toBe(10);
      expect(BASELINE.LOCKOUT_MIN_DURATION_SEC).toBe(900);
      expect(BASELINE.SESSION_IDLE_MAX_SEC).toBe(1800);
      expect(BASELINE.SESSION_ABSOLUTE_MAX_SEC).toBe(43_200);
      expect(BASELINE.CREDENTIAL_MIN_LENGTH).toBe(8);
      expect(BASELINE.CREDENTIAL_MAX_ACCEPT_LENGTH).toBe(64);
      expect(BASELINE.RETRY_MIN_ATTEMPTS).toBe(3);
      expect(BASELINE.RETRY_MAX_ATTEMPTS).toBe(10);
      expect(BASELINE.ARGON2_MEMORY_COST_KB).toBe(65_536);
      expect(BASELINE.ARGON2_TIME_COST).toBe(3);
      expect(BASELINE.ARGON2_PARALLELISM).toBe(4);
    });
  });

  describe('string coercion from env vars', () => {
    it('coerces string numbers to integers', () => {
      const config = loadSecurityConfig({
        accessTokenLifetimeSec: '600',
        lockoutThreshold: '15',
        sessionIdleTimeoutSec: '900',
      });
      expect(config.accessTokenLifetimeSec).toBe(600);
      expect(config.lockoutThreshold).toBe(15);
      expect(config.sessionIdleTimeoutSec).toBe(900);
    });
  });

  describe('error message quality', () => {
    it('throws with field name and explanation on failure', () => {
      try {
        loadSecurityConfig({ accessTokenLifetimeSec: 9999, lockoutDurationSec: 1 });
        expect.fail('should have thrown');
      } catch (e) {
        const msg = (e as Error).message;
        expect(msg).toContain('Security configuration violates platform baselines');
        expect(msg).toContain('accessTokenLifetimeSec');
        expect(msg).toContain('lockoutDurationSec');
      }
    });
  });
});
