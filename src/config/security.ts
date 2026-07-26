import { z } from 'zod';

/**
 * Security Configuration Baseline
 *
 * Defines all security-sensitive tunables with hard minimum/maximum bounds
 * as ratified in Requirements 23.1–23.11. Deployment configuration can tune
 * within these bounds but CANNOT weaken security below platform baselines.
 *
 * Fail-fast: the service refuses to start if any supplied value violates bounds.
 */

// === Baseline Constants (non-negotiable platform security floors/ceilings) ===

export const BASELINE = {
  // R23.5: Access token lifetime ceiling
  ACCESS_TOKEN_MAX_LIFETIME_SEC: 900, // 15 minutes

  // R23.6: Refresh token lifetime ceiling
  REFRESH_TOKEN_MAX_LIFETIME_SEC: 2_592_000, // 30 days

  // R23.7: TOTP parameters (RFC 6238)
  TOTP_DIGITS: 6,
  TOTP_PERIOD_SEC: 30,
  TOTP_DRIFT_STEPS: 1, // ±1 step tolerance

  // R23.8: Lockout threshold ceiling
  LOCKOUT_MAX_THRESHOLD: 100,
  LOCKOUT_DEFAULT_THRESHOLD: 10,

  // R23.9: Lockout duration floor
  LOCKOUT_MIN_DURATION_SEC: 900, // 15 minutes

  // R23.10: Session timeout ceilings
  SESSION_IDLE_MAX_SEC: 1800, // 30 minutes
  SESSION_ABSOLUTE_MAX_SEC: 43_200, // 12 hours

  // R23.11: Retry bounds for event/webhook delivery
  RETRY_MIN_ATTEMPTS: 3,
  RETRY_MAX_ATTEMPTS: 10,

  // R23.1–R23.4: Credential/password policy baselines
  CREDENTIAL_MIN_LENGTH: 8,
  CREDENTIAL_MAX_ACCEPT_LENGTH: 64, // accept passwords up to 64 chars minimum
  CREDENTIAL_REQUIRE_BREACH_CHECK: true,

  // Argon2id parameters (OWASP recommended)
  ARGON2_MEMORY_COST_KB: 65_536, // 64 MB
  ARGON2_TIME_COST: 3,
  ARGON2_PARALLELISM: 4,

  // Rate limiting
  RATE_LIMIT_MIN_THRESHOLD: 1,
  RATE_LIMIT_MIN_WINDOW_SEC: 1,
} as const;

// === Zod schema with clamping validation ===

const securityConfigSchema = z.object({
  // Token lifetimes
  accessTokenLifetimeSec: z.coerce
    .number()
    .int()
    .min(60, 'Access token lifetime must be at least 60 seconds')
    .max(
      BASELINE.ACCESS_TOKEN_MAX_LIFETIME_SEC,
      `Access token lifetime must not exceed ${BASELINE.ACCESS_TOKEN_MAX_LIFETIME_SEC}s (15 min)`,
    )
    .default(900),

  refreshTokenLifetimeSec: z.coerce
    .number()
    .int()
    .min(3600, 'Refresh token lifetime must be at least 1 hour')
    .max(
      BASELINE.REFRESH_TOKEN_MAX_LIFETIME_SEC,
      `Refresh token lifetime must not exceed ${BASELINE.REFRESH_TOKEN_MAX_LIFETIME_SEC}s (30 days)`,
    )
    .default(604_800), // 7 days default

  // TOTP (fixed, not configurable — deviation breaks RFC 6238 interop)
  totpDigits: z.literal(BASELINE.TOTP_DIGITS).default(BASELINE.TOTP_DIGITS),
  totpPeriodSec: z.literal(BASELINE.TOTP_PERIOD_SEC).default(BASELINE.TOTP_PERIOD_SEC),
  totpDriftSteps: z.literal(BASELINE.TOTP_DRIFT_STEPS).default(BASELINE.TOTP_DRIFT_STEPS),

  // Lockout
  lockoutThreshold: z.coerce
    .number()
    .int()
    .min(3, 'Lockout threshold must be at least 3')
    .max(
      BASELINE.LOCKOUT_MAX_THRESHOLD,
      `Lockout threshold must not exceed ${BASELINE.LOCKOUT_MAX_THRESHOLD}`,
    )
    .default(BASELINE.LOCKOUT_DEFAULT_THRESHOLD),

  lockoutDurationSec: z.coerce
    .number()
    .int()
    .min(
      BASELINE.LOCKOUT_MIN_DURATION_SEC,
      `Lockout duration must be at least ${BASELINE.LOCKOUT_MIN_DURATION_SEC}s (15 min)`,
    )
    .default(BASELINE.LOCKOUT_MIN_DURATION_SEC),

  // Session timeouts
  sessionIdleTimeoutSec: z.coerce
    .number()
    .int()
    .min(60, 'Session idle timeout must be at least 60 seconds')
    .max(
      BASELINE.SESSION_IDLE_MAX_SEC,
      `Session idle timeout must not exceed ${BASELINE.SESSION_IDLE_MAX_SEC}s (30 min)`,
    )
    .default(BASELINE.SESSION_IDLE_MAX_SEC),

  sessionAbsoluteTimeoutSec: z.coerce
    .number()
    .int()
    .min(300, 'Session absolute timeout must be at least 5 minutes')
    .max(
      BASELINE.SESSION_ABSOLUTE_MAX_SEC,
      `Session absolute timeout must not exceed ${BASELINE.SESSION_ABSOLUTE_MAX_SEC}s (12 h)`,
    )
    .default(BASELINE.SESSION_ABSOLUTE_MAX_SEC),

  // Concurrent sessions per identity
  maxConcurrentSessions: z.coerce.number().int().min(1).max(100).default(5),

  // Retry/backoff for event delivery and webhooks
  retryMaxAttempts: z.coerce
    .number()
    .int()
    .min(BASELINE.RETRY_MIN_ATTEMPTS, `Retry attempts must be at least ${BASELINE.RETRY_MIN_ATTEMPTS}`)
    .max(BASELINE.RETRY_MAX_ATTEMPTS, `Retry attempts must not exceed ${BASELINE.RETRY_MAX_ATTEMPTS}`)
    .default(5),

  retryBaseDelayMs: z.coerce.number().int().min(100).max(30_000).default(1000),

  // Credential/password policy
  credentialMinLength: z.coerce
    .number()
    .int()
    .min(
      BASELINE.CREDENTIAL_MIN_LENGTH,
      `Credential minimum length must be at least ${BASELINE.CREDENTIAL_MIN_LENGTH}`,
    )
    .default(BASELINE.CREDENTIAL_MIN_LENGTH),

  credentialMaxAcceptLength: z.coerce
    .number()
    .int()
    .min(
      BASELINE.CREDENTIAL_MAX_ACCEPT_LENGTH,
      `Must accept passwords of at least ${BASELINE.CREDENTIAL_MAX_ACCEPT_LENGTH} characters`,
    )
    .default(128),

  credentialRequireBreachCheck: z.boolean().default(BASELINE.CREDENTIAL_REQUIRE_BREACH_CHECK),

  // Argon2id hashing parameters
  argon2MemoryCostKb: z.coerce
    .number()
    .int()
    .min(BASELINE.ARGON2_MEMORY_COST_KB, 'Argon2 memory cost must be at least 64 MB')
    .default(BASELINE.ARGON2_MEMORY_COST_KB),

  argon2TimeCost: z.coerce
    .number()
    .int()
    .min(BASELINE.ARGON2_TIME_COST, 'Argon2 time cost must be at least 3')
    .default(BASELINE.ARGON2_TIME_COST),

  argon2Parallelism: z.coerce
    .number()
    .int()
    .min(1)
    .max(16)
    .default(BASELINE.ARGON2_PARALLELISM),

  // Rate limiting defaults
  rateLimitDefaultThreshold: z.coerce
    .number()
    .int()
    .min(BASELINE.RATE_LIMIT_MIN_THRESHOLD)
    .default(100),

  rateLimitDefaultWindowSec: z.coerce
    .number()
    .int()
    .min(BASELINE.RATE_LIMIT_MIN_WINDOW_SEC)
    .default(60),

  // Verification token expiry
  verificationTokenExpirySec: z.coerce.number().int().min(300).max(86_400).default(3600),
  resetTokenExpirySec: z.coerce.number().int().min(300).max(900).default(900),
  passwordlessTokenExpirySec: z.coerce.number().int().min(60).max(900).default(600),
});

export type SecurityConfig = z.infer<typeof securityConfigSchema>;

/**
 * Load and validate security configuration.
 * Reads from environment variables prefixed with SECURITY_ or uses defaults.
 * Throws at startup if any value violates the platform security baseline.
 */
export function loadSecurityConfig(overrides?: Partial<Record<string, unknown>>): SecurityConfig {
  const input = overrides ?? {
    accessTokenLifetimeSec: process.env['SECURITY_ACCESS_TOKEN_LIFETIME_SEC'],
    refreshTokenLifetimeSec: process.env['SECURITY_REFRESH_TOKEN_LIFETIME_SEC'],
    lockoutThreshold: process.env['SECURITY_LOCKOUT_THRESHOLD'],
    lockoutDurationSec: process.env['SECURITY_LOCKOUT_DURATION_SEC'],
    sessionIdleTimeoutSec: process.env['SECURITY_SESSION_IDLE_TIMEOUT_SEC'],
    sessionAbsoluteTimeoutSec: process.env['SECURITY_SESSION_ABSOLUTE_TIMEOUT_SEC'],
    maxConcurrentSessions: process.env['SECURITY_MAX_CONCURRENT_SESSIONS'],
    retryMaxAttempts: process.env['SECURITY_RETRY_MAX_ATTEMPTS'],
    retryBaseDelayMs: process.env['SECURITY_RETRY_BASE_DELAY_MS'],
    credentialMinLength: process.env['SECURITY_CREDENTIAL_MIN_LENGTH'],
    credentialMaxAcceptLength: process.env['SECURITY_CREDENTIAL_MAX_ACCEPT_LENGTH'],
    rateLimitDefaultThreshold: process.env['SECURITY_RATE_LIMIT_THRESHOLD'],
    rateLimitDefaultWindowSec: process.env['SECURITY_RATE_LIMIT_WINDOW_SEC'],
    verificationTokenExpirySec: process.env['SECURITY_VERIFICATION_TOKEN_EXPIRY_SEC'],
    resetTokenExpirySec: process.env['SECURITY_RESET_TOKEN_EXPIRY_SEC'],
    passwordlessTokenExpirySec: process.env['SECURITY_PASSWORDLESS_TOKEN_EXPIRY_SEC'],
  };

  // Remove undefined values so Zod applies defaults
  const cleaned = Object.fromEntries(
    Object.entries(input).filter(([_, v]) => v !== undefined && v !== null && v !== ''),
  );

  const result = securityConfigSchema.safeParse(cleaned);

  if (!result.success) {
    const errors = result.error.flatten().fieldErrors;
    const message = Object.entries(errors)
      .map(([field, msgs]) => `  ${field}: ${(msgs ?? []).join(', ')}`)
      .join('\n');
    throw new Error(
      `Security configuration violates platform baselines. Service cannot start.\n${message}`,
    );
  }

  return result.data;
}

// Singleton instance — loaded once at service startup
let _securityConfig: SecurityConfig | null = null;

export function getSecurityConfig(): SecurityConfig {
  if (!_securityConfig) {
    _securityConfig = loadSecurityConfig();
  }
  return _securityConfig;
}

// For testing — reset the singleton
export function resetSecurityConfig(): void {
  _securityConfig = null;
}
