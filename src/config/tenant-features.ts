import { ComplianceProfileId, ComplianceRequirements, mergeComplianceProfiles } from './compliance-profiles.js';

export type FeatureId =
  | 'auth.password' | 'auth.passwordless' | 'auth.passkey' | 'auth.social'
  | 'auth.saml' | 'auth.oidc_federation' | 'auth.device_trust' | 'auth.biometric' | 'auth.certificate'
  | 'mfa.totp' | 'mfa.sms' | 'mfa.email' | 'mfa.push' | 'mfa.fido2' | 'mfa.biometric'
  | 'session.sso' | 'session.concurrent_limit' | 'session.device_binding'
  | 'authz.rbac' | 'authz.abac' | 'authz.policy_engine' | 'authz.resource_level'
  | 'security.risk_engine' | 'security.anomaly_detection' | 'security.ip_whitelist'
  | 'security.geo_restriction' | 'security.impossible_travel' | 'security.brute_force_protection'
  | 'identity.self_registration' | 'identity.admin_provisioning' | 'identity.scim'
  | 'identity.directory_sync' | 'identity.guest_users' | 'identity.service_accounts' | 'identity.machine_identities'
  | 'data.encryption_at_rest' | 'data.residency' | 'data.right_to_erasure' | 'data.consent_management' | 'data.export'
  | 'integration.webhooks' | 'integration.events' | 'integration.sdk' | 'integration.api_keys'
  | 'audit.basic' | 'audit.signed' | 'audit.real_time_alerts' | 'audit.compliance_reports'
  | 'branding.custom_domain' | 'branding.custom_ui' | 'branding.email_templates';

export interface TenantFeatureConfig {
  tenantId: string;
  tenantName: string;
  industry: string;
  complianceProfiles: ComplianceProfileId[];
  enabledFeatures: FeatureId[];
  customOverrides?: Partial<ComplianceRequirements>;
  metadata?: Record<string, unknown>;
}

export function resolveEffectiveRequirements(tenantConfig: TenantFeatureConfig): ComplianceRequirements {
  const profiles: ComplianceProfileId[] = ['base', ...tenantConfig.complianceProfiles];
  const merged = mergeComplianceProfiles(profiles);
  if (tenantConfig.customOverrides) {
    const o = tenantConfig.customOverrides;
    return {
      ...merged,
      ...(o.passwordMinLength !== undefined && o.passwordMinLength > merged.passwordMinLength ? { passwordMinLength: o.passwordMinLength } : {}),
      ...(o.sessionIdleTimeoutSec !== undefined && o.sessionIdleTimeoutSec < merged.sessionIdleTimeoutSec ? { sessionIdleTimeoutSec: o.sessionIdleTimeoutSec } : {}),
      ...(o.sessionAbsoluteTimeoutSec !== undefined && o.sessionAbsoluteTimeoutSec < merged.sessionAbsoluteTimeoutSec ? { sessionAbsoluteTimeoutSec: o.sessionAbsoluteTimeoutSec } : {}),
      ...(o.lockoutThreshold !== undefined && o.lockoutThreshold < merged.lockoutThreshold ? { lockoutThreshold: o.lockoutThreshold } : {}),
      ...(o.auditRetentionDays !== undefined && o.auditRetentionDays > merged.auditRetentionDays ? { auditRetentionDays: o.auditRetentionDays } : {}),
      ...(o.mfaRequired === true ? { mfaRequired: true } : {}),
      ...(o.auditSignedEntries === true ? { auditSignedEntries: true } : {}),
      ...(o.dataResidencyEnforced === true ? { dataResidencyEnforced: true } : {}),
      ...(o.anomalyDetectionRequired === true ? { anomalyDetectionRequired: true } : {}),
    };
  }
  return merged;
}

export function isFeatureEnabled(tenantConfig: TenantFeatureConfig, feature: FeatureId): boolean {
  return tenantConfig.enabledFeatures.includes(feature);
}

export function validateTenantCompliance(tenantConfig: TenantFeatureConfig): string[] {
  const requirements = resolveEffectiveRequirements(tenantConfig);
  const violations: string[] = [];
  if (requirements.mfaRequired && !tenantConfig.enabledFeatures.some((f) => f.startsWith('mfa.'))) violations.push('Compliance requires MFA but no MFA method is enabled');
  if (requirements.rbacRequired && !isFeatureEnabled(tenantConfig, 'authz.rbac')) violations.push('Compliance requires RBAC but authz.rbac is not enabled');
  if (requirements.abacSupported && !isFeatureEnabled(tenantConfig, 'authz.abac')) violations.push('Compliance requires ABAC but authz.abac is not enabled');
  if (requirements.dataEncryptionAtRest && !isFeatureEnabled(tenantConfig, 'data.encryption_at_rest')) violations.push('Compliance requires encryption at rest but data.encryption_at_rest is not enabled');
  if (requirements.rightToErasure && !isFeatureEnabled(tenantConfig, 'data.right_to_erasure')) violations.push('Compliance requires right to erasure but data.right_to_erasure is not enabled');
  if (requirements.consentManagementRequired && !isFeatureEnabled(tenantConfig, 'data.consent_management')) violations.push('Compliance requires consent management but data.consent_management is not enabled');
  if (requirements.auditSignedEntries && !isFeatureEnabled(tenantConfig, 'audit.signed')) violations.push('Compliance requires signed audit entries but audit.signed is not enabled');
  if (requirements.anomalyDetectionRequired && !isFeatureEnabled(tenantConfig, 'security.anomaly_detection')) violations.push('Compliance requires anomaly detection but security.anomaly_detection is not enabled');
  if (requirements.webhookSigningRequired && !isFeatureEnabled(tenantConfig, 'integration.webhooks')) violations.push('Compliance requires webhook signing but integration.webhooks is not enabled');
  return violations;
}
