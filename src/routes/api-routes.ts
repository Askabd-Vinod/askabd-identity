import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { sendError, sendServerError, extractOrgContext } from './error-handler.js';
import { getPool } from '../db/index.js';
import { AuditLogger } from '../services/audit-logger.js';
import { EventPublisher } from '../services/event-publisher.js';
import { IdentityManager } from '../services/identity-manager.js';
import { CredentialManager } from '../services/credential-manager.js';
import { SessionManager } from '../services/session-manager.js';
import { TokenService } from '../services/token-service.js';
import { MfaService } from '../services/mfa-service.js';
import { RateLimiter } from '../services/rate-limiter.js';
import { AuthService } from '../services/auth-service.js';
import { AuthorizationService } from '../services/authorization-service.js';
import { WebhookDispatcher } from '../services/webhook-dispatcher.js';

export async function apiRoutes(server: FastifyInstance): Promise<void> {
  const pool = getPool();
  const auditLogger = new AuditLogger(pool);
  const eventPublisher = new EventPublisher();
  const identityManager = new IdentityManager(pool, auditLogger, eventPublisher);
  const credentialManager = new CredentialManager(pool, auditLogger, eventPublisher);
  const sessionManager = new SessionManager(pool, auditLogger, eventPublisher);
  const tokenService = new TokenService(pool, auditLogger, eventPublisher);
  const mfaService = new MfaService(pool, auditLogger, eventPublisher);
  const rateLimiter = new RateLimiter();
  const authService = new AuthService(pool, auditLogger, eventPublisher, credentialManager, sessionManager, tokenService, mfaService, rateLimiter);
  const authzService = new AuthorizationService(pool, auditLogger, eventPublisher);
  const webhookDispatcher = new WebhookDispatcher(pool);

  server.post('/identities', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', field: 'X-Org-Context', message: 'X-Org-Context header is required (1..255 chars)' } });
    const body = req.body as any;
    const result = await identityManager.createIdentity({ identifier: body.identifier ?? '', orgContext, identityType: body.identityType, profile: body.profile });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(201).send(result.value);
  });

  server.post('/identities/:id/verify', async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as any;
    const body = req.body as any;
    const result = await identityManager.verify({ identityId: id, token: body.token ?? '' });
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.post('/identities/:id/credential/store', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const body = req.body as any;
    const result = await credentialManager.storeCredential(id, body.credential ?? '', orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/identities/:id/credential/change', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const body = req.body as any;
    const result = await credentialManager.changeCredential({ identityId: id, currentCredential: body.currentCredential ?? '', newCredential: body.newCredential ?? '', orgContext, sessionId: body.sessionId });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/credential/reset/request', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const identity = await identityManager.getByIdentifier(body.identifier ?? '', orgContext);
    await credentialManager.issueResetToken(identity?.id ?? null, orgContext);
    reply.send({ accepted: true });
  });

  server.post('/credential/reset/confirm', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await credentialManager.resetCredential({ token: body.token ?? '', newCredential: body.newCredential ?? '', orgContext });
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.post('/auth/login', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authService.login({ identifier: body.identifier ?? '', credential: body.credential ?? '', orgContext, mfaCode: body.mfaCode, clientId: req.ip });
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.post('/auth/logout', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authService.logout(body.sessionId ?? '', orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/tokens/validate', async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const result = await tokenService.validate(body.accessToken ?? '');
    reply.send(result);
  });

  server.post('/tokens/refresh', async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as any;
    const result = await tokenService.refresh(body.refreshToken ?? '', body.sessionId ?? '');
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.post('/tokens/revoke', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await tokenService.revoke(body.tokenId ?? '', orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.get('/identities/:id/sessions', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const sessions = await sessionManager.list(id, orgContext);
    reply.send({ sessions });
  });

  server.post('/sessions/:id/validate', async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as any;
    reply.send(await sessionManager.validate(id));
  });

  server.delete('/sessions/:id', async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = req.params as any;
    const result = await sessionManager.terminate(id);
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/identities/:id/mfa/enroll', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const result = await mfaService.enroll(id, orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.post('/identities/:id/mfa/activate', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const body = req.body as any;
    const result = await mfaService.activate(id, body.code ?? '', orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/identities/:id/mfa/disable', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const { id } = req.params as any;
    const body = req.body as any;
    const result = await mfaService.disable(id, body.code ?? '', orgContext);
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/roles', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authzService.createRole({ name: body.name ?? '', orgContext, permissions: body.permissions ?? [] });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(201).send(result.value);
  });

  server.post('/roles/assign', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authzService.assignRole({ identityId: body.identityId ?? '', roleId: body.roleId ?? '', orgContext });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/roles/revoke', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authzService.revokeRole({ identityId: body.identityId ?? '', roleId: body.roleId ?? '', orgContext });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(204).send();
  });

  server.post('/policy/check', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await authzService.check({ identityId: body.identityId ?? '', action: body.action ?? '', resourceType: body.resourceType ?? '', orgContext });
    if (!result.ok) return sendError(reply, result.error);
    reply.send(result.value);
  });

  server.get('/audit/events', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const query = req.query as any;
    try {
      const result = await auditLogger.query({ orgContext, from: new Date(query.from ?? ''), to: new Date(query.to ?? ''), limit: query.limit ? parseInt(query.limit, 10) : undefined, identityId: query.identityId, type: query.type });
      reply.send(result);
    } catch (err: any) {
      if (err.name === 'AuditValidationError') return reply.status(400).send({ error: { category: 'validation', code: 'invalid_query', field: err.field, message: err.message } });
      sendServerError(reply);
    }
  });

  server.post('/webhooks', async (req: FastifyRequest, reply: FastifyReply) => {
    const orgContext = extractOrgContext(req);
    if (!orgContext) return reply.status(400).send({ error: { category: 'validation', code: 'org_context_required', message: 'X-Org-Context required' } });
    const body = req.body as any;
    const result = await webhookDispatcher.register({ url: body.url ?? '', eventType: body.eventType ?? '', orgContext });
    if (!result.ok) return sendError(reply, result.error);
    reply.status(201).send(result.value);
  });
}
