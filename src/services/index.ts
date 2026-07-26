export { AuditLogger, AuditValidationError, type AuditEvent, type RecordAuditInput, type QueryAuditInput } from './audit-logger.js';
export { EventPublisher, getEventPublisher, resetEventPublisher, type DomainEvent } from './event-publisher.js';
export { IdentityManager, type Identity, type CreateIdentityInput, type VerifyIdentityInput, type Result, type DomainError } from './identity-manager.js';
export { CredentialManager } from './credential-manager.js';
