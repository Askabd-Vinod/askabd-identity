import { FastifyReply } from 'fastify';
import { FastifyRequest } from 'fastify';
import { type DomainError } from '../services/identity-manager.js';

const CATEGORY_STATUS_MAP: Record<string, number> = {
  validation: 400, authentication: 401, authorization: 403,
  not_found: 404, conflict: 409, rate_limited: 429, expired: 401, server: 500,
};

export function mapErrorToResponse(error: DomainError): { statusCode: number; body: object } {
  const statusCode = CATEGORY_STATUS_MAP[error.category] ?? 500;
  return { statusCode, body: { error: { category: error.category, code: error.code, field: error.field ?? null, message: error.message, retryAfterMs: (error as any).retryAfterMs ?? null } } };
}

export function sendError(reply: FastifyReply, error: DomainError): void {
  const { statusCode, body } = mapErrorToResponse(error);
  reply.status(statusCode).send(body);
}

export function sendServerError(reply: FastifyReply): void {
  reply.status(500).send({ error: { category: 'server', code: 'internal_error', field: null, message: 'An unexpected error occurred', retryAfterMs: null } });
}

export function extractOrgContext(request: FastifyRequest): string | null {
  const header = request.headers['x-org-context'];
  if (typeof header === 'string' && header.length >= 1 && header.length <= 255) return header;
  return null;
}
