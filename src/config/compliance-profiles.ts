/**
 * Compliance Profiles
 *
 * Industry-standard compliance baselines that can be assigned to any tenant.
 * Each profile enforces NFRs based on real regulatory/framework requirements.
 * Tenants can have MULTIPLE profiles (e.g., a healthcare fintech needs both HIPAA + PCI-DSS).
 *
 * The platform enforces the STRICTEST value across all active profiles.
 */

export type ComplianceProfileId =
  | 'base'
  | 'soc2'
  | 'iso27001'
  | 'hipaa'
  | 'pci_dss'
  | 'gdpr'
  | 'sox'
  | 'fedramp'
  | 'nist_800_53'
  | 'ccpa'
  | 'psd2'
  | 'rbi'
  | 'dpdpa'
  | 'education'
  | 'insurance'
  | 'telecom';

export interface ComplianceProfile {
  id: ComplianceProfileId;
  name: string;
  description: string;
  requirements: ComplianceRequirements;
}

export interface ComplianceRequirements {
  mfaRequired: boolean;
  mfaForAdmins: boolean;
  passwordMinLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireNumbers: boolean;
  passwordRequireSpecial: boolean;
  passwordHistoryCount: number;
  passwordMaxAgeDays: number;
  passwordBreachCheckRequired: boolean;
  sessionIdleTimeoutSec: number;
  sessionAbsoluteTimeoutSec: number;
  accessTokenMaxLifetimeSec: number;
  refreshTokenMaxLifetimeSec: number;
  concurrentSessionLimit: number;
  lockoutThreshold: number;
  lockoutDurationSec: number;
  auditRetentionDays: number;
  auditImmutable: boolean;
  auditSignedEntries: boolean;
  auditRealTimeAlerts: boolean;
  dataEncryptionAtRest: boolean;
  dataEncryptionInTransit: boolean;
  dataResidencyEnforced: boolean;
  piiMaskingInLogs: boolean;
  rightToErasure: boolean;
  consentManagementRequired: boolean;
  dataProcessingAgreementRequired: boolean;
  rbacRequired: boolean;
  abacSupported: boolean;
  leastPrivilegeEnforced: boolean;
  separationOfDutiesRequired: boolean;
  privilegedAccessReviewDays: number;
  ipWhitelistSupported: boolean;
  geoRestrictionSupported: boolean;
  rateLimitPerTenant: boolean;
  ddosProtectionRequired: boolean;
  tlsMinVersion: '1.2' | '1.3';
  anomalyDetectionRequired: boolean;
  incidentResponsePlanRequired: boolean;
  breachNotificationHours: number;
  keyRotationDays: number;
  hsmRequired: boolean;
  uptimeSlaPercent: number;
  rpoMinutes: number;
  rtoMinutes: number;
  backupFrequencyHours: number;
  apiRateLimitPerMinute: number;
  apiVersioningRequired: boolean;
  webhookSigningRequired: boolean;
}

const BASE_REQUIREMENTS: ComplianceRequirements = {
  mfaRequired: false, mfaForAdmins: true, passwordMinLength: 8,
  passwordRequireUppercase: true, passwordRequireLowercase: true,
  passwordRequireNumbers: true, passwordRequireSpecial: false,
  passwordHistoryCount: 3, passwordMaxAgeDays: 0, passwordBreachCheckRequired: true,
  sessionIdleTimeoutSec: 1800, sessionAbsoluteTimeoutSec: 43200,
  accessTokenMaxLifetimeSec: 900, refreshTokenMaxLifetimeSec: 2592000,
  concurrentSessionLimit: 5, lockoutThreshold: 10, lockoutDurationSec: 900,
  auditRetentionDays: 90, auditImmutable: true, auditSignedEntries: false, auditRealTimeAlerts: false,
  dataEncryptionAtRest: true, dataEncryptionInTransit: true, dataResidencyEnforced: false,
  piiMaskingInLogs: true, rightToErasure: false, consentManagementRequired: false,
  dataProcessingAgreementRequired: false, rbacRequired: true, abacSupported: false,
  leastPrivilegeEnforced: true, separationOfDutiesRequired: false, privilegedAccessReviewDays: 90,
  ipWhitelistSupported: true, geoRestrictionSupported: false, rateLimitPerTenant: true,
  ddosProtectionRequired: false, tlsMinVersion: '1.2', anomalyDetectionRequired: false,
  incidentResponsePlanRequired: false, breachNotificationHours: 72, keyRotationDays: 90,
  hsmRequired: false, uptimeSlaPercent: 99.5, rpoMinutes: 60, rtoMinutes: 240,
  backupFrequencyHours: 24, apiRateLimitPerMinute: 1000, apiVersioningRequired: true,
  webhookSigningRequired: true,
};

export const COMPLIANCE_PROFILES: Record<ComplianceProfileId, ComplianceProfile> = {
  base: { id: 'base', name: 'Platform Baseline', description: 'Minimum security baseline for all tenants.', requirements: BASE_REQUIREMENTS },
  soc2: { id: 'soc2', name: 'SOC 2 Type II', description: 'AICPA Trust Services Criteria.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordRequireSpecial: true, passwordHistoryCount: 12, passwordMaxAgeDays: 90, sessionIdleTimeoutSec: 900, sessionAbsoluteTimeoutSec: 28800, lockoutThreshold: 5, auditRetentionDays: 365, auditSignedEntries: true, auditRealTimeAlerts: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 30, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 24, uptimeSlaPercent: 99.9, rpoMinutes: 15, rtoMinutes: 60, backupFrequencyHours: 4 } },
  iso27001: { id: 'iso27001', name: 'ISO 27001:2022', description: 'International information security management.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 10, passwordRequireSpecial: true, passwordHistoryCount: 6, passwordMaxAgeDays: 180, lockoutThreshold: 5, auditRetentionDays: 365, auditSignedEntries: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 30, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, keyRotationDays: 365, uptimeSlaPercent: 99.9, rpoMinutes: 30, rtoMinutes: 120, backupFrequencyHours: 12 } },
  hipaa: { id: 'hipaa', name: 'HIPAA', description: 'Protected health information.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordRequireSpecial: true, passwordHistoryCount: 12, passwordMaxAgeDays: 60, sessionIdleTimeoutSec: 600, sessionAbsoluteTimeoutSec: 14400, concurrentSessionLimit: 2, lockoutThreshold: 3, lockoutDurationSec: 1800, auditRetentionDays: 2190, auditSignedEntries: true, auditRealTimeAlerts: true, dataResidencyEnforced: true, dataProcessingAgreementRequired: true, abacSupported: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 30, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 24, uptimeSlaPercent: 99.9, rpoMinutes: 15, rtoMinutes: 30, backupFrequencyHours: 1 } },
  pci_dss: { id: 'pci_dss', name: 'PCI-DSS v4.0', description: 'Cardholder data protection.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordRequireSpecial: true, passwordHistoryCount: 12, passwordMaxAgeDays: 90, sessionIdleTimeoutSec: 900, sessionAbsoluteTimeoutSec: 28800, concurrentSessionLimit: 1, lockoutThreshold: 6, lockoutDurationSec: 1800, auditRetentionDays: 365, auditSignedEntries: true, auditRealTimeAlerts: true, dataResidencyEnforced: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 30, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 24, hsmRequired: true, uptimeSlaPercent: 99.99, rpoMinutes: 5, rtoMinutes: 15, backupFrequencyHours: 1, apiRateLimitPerMinute: 500 } },
  gdpr: { id: 'gdpr', name: 'GDPR', description: 'EU data protection.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 10, auditRetentionDays: 365, dataResidencyEnforced: true, rightToErasure: true, consentManagementRequired: true, dataProcessingAgreementRequired: true, anomalyDetectionRequired: true, breachNotificationHours: 72 } },
  sox: { id: 'sox', name: 'SOX', description: 'Financial reporting controls.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordHistoryCount: 24, passwordMaxAgeDays: 60, sessionIdleTimeoutSec: 900, auditRetentionDays: 2555, auditSignedEntries: true, auditRealTimeAlerts: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 14, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, uptimeSlaPercent: 99.9 } },
  fedramp: { id: 'fedramp', name: 'FedRAMP', description: 'US Federal authorization.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 15, passwordRequireSpecial: true, passwordHistoryCount: 24, passwordMaxAgeDays: 60, sessionIdleTimeoutSec: 900, sessionAbsoluteTimeoutSec: 14400, concurrentSessionLimit: 3, lockoutThreshold: 3, lockoutDurationSec: 3600, auditRetentionDays: 365, auditSignedEntries: true, auditRealTimeAlerts: true, dataResidencyEnforced: true, abacSupported: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 14, geoRestrictionSupported: true, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 1, hsmRequired: true, uptimeSlaPercent: 99.99, rpoMinutes: 5, rtoMinutes: 15, backupFrequencyHours: 1 } },
  nist_800_53: { id: 'nist_800_53', name: 'NIST 800-53', description: 'US federal cybersecurity controls.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 14, passwordRequireSpecial: true, passwordHistoryCount: 24, passwordMaxAgeDays: 60, sessionIdleTimeoutSec: 900, concurrentSessionLimit: 3, lockoutThreshold: 3, lockoutDurationSec: 3600, auditRetentionDays: 365, auditSignedEntries: true, auditRealTimeAlerts: true, abacSupported: true, separationOfDutiesRequired: true, privilegedAccessReviewDays: 14, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 1, hsmRequired: true } },
  ccpa: { id: 'ccpa', name: 'CCPA', description: 'California consumer privacy.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, auditRetentionDays: 365, rightToErasure: true, consentManagementRequired: true, dataProcessingAgreementRequired: true, breachNotificationHours: 72 } },
  psd2: { id: 'psd2', name: 'PSD2', description: 'EU payment services directive.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, sessionIdleTimeoutSec: 300, sessionAbsoluteTimeoutSec: 7200, concurrentSessionLimit: 1, lockoutThreshold: 5, auditRetentionDays: 1825, auditSignedEntries: true, dataResidencyEnforced: true, anomalyDetectionRequired: true, breachNotificationHours: 24, uptimeSlaPercent: 99.99, apiRateLimitPerMinute: 300 } },
  rbi: { id: 'rbi', name: 'RBI Guidelines', description: 'Reserve Bank of India digital payment security.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordRequireSpecial: true, passwordMaxAgeDays: 90, sessionIdleTimeoutSec: 300, sessionAbsoluteTimeoutSec: 7200, concurrentSessionLimit: 1, lockoutThreshold: 3, lockoutDurationSec: 1800, auditRetentionDays: 3650, auditSignedEntries: true, auditRealTimeAlerts: true, dataResidencyEnforced: true, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 6, uptimeSlaPercent: 99.9 } },
  dpdpa: { id: 'dpdpa', name: 'DPDPA (India)', description: 'India data protection act.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, auditRetentionDays: 365, dataResidencyEnforced: true, rightToErasure: true, consentManagementRequired: true, dataProcessingAgreementRequired: true, breachNotificationHours: 72 } },
  education: { id: 'education', name: 'FERPA + COPPA', description: 'Education records + children privacy.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 10, sessionIdleTimeoutSec: 900, auditRetentionDays: 2190, consentManagementRequired: true, dataProcessingAgreementRequired: true, anomalyDetectionRequired: true, breachNotificationHours: 24 } },
  insurance: { id: 'insurance', name: 'Insurance (IRDAI)', description: 'Insurance regulatory guidelines.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 12, passwordMaxAgeDays: 90, sessionIdleTimeoutSec: 600, auditRetentionDays: 3650, auditSignedEntries: true, dataResidencyEnforced: true, anomalyDetectionRequired: true, incidentResponsePlanRequired: true, breachNotificationHours: 24 } },
  telecom: { id: 'telecom', name: 'Telecom (TRAI)', description: 'Telecom regulatory guidelines.', requirements: { ...BASE_REQUIREMENTS, mfaRequired: true, passwordMinLength: 10, sessionIdleTimeoutSec: 600, auditRetentionDays: 1825, dataResidencyEnforced: true, consentManagementRequired: true, anomalyDetectionRequired: true, breachNotificationHours: 24 } },
};

export function mergeComplianceProfiles(profileIds: ComplianceProfileId[]): ComplianceRequirements {
  const profiles = profileIds.map((id) => COMPLIANCE_PROFILES[id]?.requirements).filter(Boolean);
  if (profiles.length === 0) return COMPLIANCE_PROFILES.base.requirements;
  return {
    mfaRequired: profiles.some((p) => p.mfaRequired),
    mfaForAdmins: profiles.some((p) => p.mfaForAdmins),
    passwordMinLength: Math.max(...profiles.map((p) => p.passwordMinLength)),
    passwordRequireUppercase: profiles.some((p) => p.passwordRequireUppercase),
    passwordRequireLowercase: profiles.some((p) => p.passwordRequireLowercase),
    passwordRequireNumbers: profiles.some((p) => p.passwordRequireNumbers),
    passwordRequireSpecial: profiles.some((p) => p.passwordRequireSpecial),
    passwordHistoryCount: Math.max(...profiles.map((p) => p.passwordHistoryCount)),
    passwordMaxAgeDays: Math.min(...profiles.map((p) => p.passwordMaxAgeDays).filter((d) => d > 0)) || 0,
    passwordBreachCheckRequired: profiles.some((p) => p.passwordBreachCheckRequired),
    sessionIdleTimeoutSec: Math.min(...profiles.map((p) => p.sessionIdleTimeoutSec)),
    sessionAbsoluteTimeoutSec: Math.min(...profiles.map((p) => p.sessionAbsoluteTimeoutSec)),
    accessTokenMaxLifetimeSec: Math.min(...profiles.map((p) => p.accessTokenMaxLifetimeSec)),
    refreshTokenMaxLifetimeSec: Math.min(...profiles.map((p) => p.refreshTokenMaxLifetimeSec)),
    concurrentSessionLimit: Math.min(...profiles.map((p) => p.concurrentSessionLimit)),
    lockoutThreshold: Math.min(...profiles.map((p) => p.lockoutThreshold)),
    lockoutDurationSec: Math.max(...profiles.map((p) => p.lockoutDurationSec)),
    auditRetentionDays: Math.max(...profiles.map((p) => p.auditRetentionDays)),
    auditImmutable: profiles.some((p) => p.auditImmutable),
    auditSignedEntries: profiles.some((p) => p.auditSignedEntries),
    auditRealTimeAlerts: profiles.some((p) => p.auditRealTimeAlerts),
    dataEncryptionAtRest: profiles.some((p) => p.dataEncryptionAtRest),
    dataEncryptionInTransit: profiles.some((p) => p.dataEncryptionInTransit),
    dataResidencyEnforced: profiles.some((p) => p.dataResidencyEnforced),
    piiMaskingInLogs: profiles.some((p) => p.piiMaskingInLogs),
    rightToErasure: profiles.some((p) => p.rightToErasure),
    consentManagementRequired: profiles.some((p) => p.consentManagementRequired),
    dataProcessingAgreementRequired: profiles.some((p) => p.dataProcessingAgreementRequired),
    rbacRequired: profiles.some((p) => p.rbacRequired),
    abacSupported: profiles.some((p) => p.abacSupported),
    leastPrivilegeEnforced: profiles.some((p) => p.leastPrivilegeEnforced),
    separationOfDutiesRequired: profiles.some((p) => p.separationOfDutiesRequired),
    privilegedAccessReviewDays: Math.min(...profiles.map((p) => p.privilegedAccessReviewDays)),
    ipWhitelistSupported: profiles.some((p) => p.ipWhitelistSupported),
    geoRestrictionSupported: profiles.some((p) => p.geoRestrictionSupported),
    rateLimitPerTenant: profiles.some((p) => p.rateLimitPerTenant),
    ddosProtectionRequired: profiles.some((p) => p.ddosProtectionRequired),
    tlsMinVersion: profiles.some((p) => p.tlsMinVersion === '1.3') ? '1.3' : '1.2',
    anomalyDetectionRequired: profiles.some((p) => p.anomalyDetectionRequired),
    incidentResponsePlanRequired: profiles.some((p) => p.incidentResponsePlanRequired),
    breachNotificationHours: Math.min(...profiles.map((p) => p.breachNotificationHours)),
    keyRotationDays: Math.min(...profiles.map((p) => p.keyRotationDays)),
    hsmRequired: profiles.some((p) => p.hsmRequired),
    uptimeSlaPercent: Math.max(...profiles.map((p) => p.uptimeSlaPercent)),
    rpoMinutes: Math.min(...profiles.map((p) => p.rpoMinutes)),
    rtoMinutes: Math.min(...profiles.map((p) => p.rtoMinutes)),
    backupFrequencyHours: Math.min(...profiles.map((p) => p.backupFrequencyHours)),
    apiRateLimitPerMinute: Math.min(...profiles.map((p) => p.apiRateLimitPerMinute)),
    apiVersioningRequired: profiles.some((p) => p.apiVersioningRequired),
    webhookSigningRequired: profiles.some((p) => p.webhookSigningRequired),
  };
}
