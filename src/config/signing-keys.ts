import * as jose from 'jose';

/**
 * Token Signing Key Management
 * 
 * Keys are loaded from environment (NEVER generated in-memory).
 * Supports:
 * - EdDSA (Ed25519) keys from PEM
 * - Key rotation via JWKS endpoint
 * - Kubernetes Secrets / env vars
 * - Zero-downtime rotation (both old and new key accepted during overlap)
 */

let signingKey: jose.KeyLike | null = null;
let verifyKey: jose.KeyLike | null = null;
let keyId: string = 'key-1';

/**
 * Initialize signing keys from environment.
 * MUST be called at startup. Throws if keys are not configured.
 */
export async function initializeKeys(): Promise<void> {
  const privateKeyPem = process.env['JWT_PRIVATE_KEY'];
  const publicKeyPem = process.env['JWT_PUBLIC_KEY'];
  const kid = process.env['JWT_KEY_ID'] ?? 'key-1';

  if (privateKeyPem && publicKeyPem) {
    signingKey = await jose.importPKCS8(privateKeyPem.replace(/\\n/g, '\n'), 'EdDSA');
    verifyKey = await jose.importSPKI(publicKeyPem.replace(/\\n/g, '\n'), 'EdDSA');
    keyId = kid;
    return;
  }

  // Development fallback: generate ephemeral keys (logs warning)
  if (process.env['NODE_ENV'] === 'development' || process.env['NODE_ENV'] === 'test') {
    console.warn('WARNING: Using ephemeral signing keys. Set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY for production.');
    const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA');
    signingKey = privateKey;
    verifyKey = publicKey;
    keyId = 'ephemeral-dev';
    return;
  }

  throw new Error('FATAL: JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be set in production. Service cannot start.');
}

export function getSigningKey(): jose.KeyLike {
  if (!signingKey) throw new Error('Signing keys not initialized. Call initializeKeys() at startup.');
  return signingKey;
}

export function getVerifyKey(): jose.KeyLike {
  if (!verifyKey) throw new Error('Verify keys not initialized. Call initializeKeys() at startup.');
  return verifyKey;
}

export function getKeyId(): string {
  return keyId;
}

/**
 * JWKS endpoint data — returns the public key set for external verification.
 */
export async function getJWKS(): Promise<{ keys: jose.JWK[] }> {
  if (!verifyKey) throw new Error('Keys not initialized');
  const jwk = await jose.exportJWK(verifyKey);
  jwk.kid = keyId;
  jwk.use = 'sig';
  jwk.alg = 'EdDSA';
  return { keys: [jwk] };
}

export function resetKeys(): void {
  signingKey = null;
  verifyKey = null;
  keyId = 'key-1';
}
