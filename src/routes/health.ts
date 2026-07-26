import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../config/env.js';

interface HealthResponse {
  status: 'ok' | 'degraded' | 'down';
  version: string;
  uptime: number;
  timestamp: string;
}

interface ReadinessResponse {
  status: 'ready' | 'not_ready';
  checks: Record<string, { status: 'up' | 'down'; latencyMs?: number }>;
}

export async function healthRoutes(server: FastifyInstance): Promise<void> {
  // Liveness probe - is the process alive?
  server.get('/health', async (_req: FastifyRequest, _reply: FastifyReply): Promise<HealthResponse> => {
    return {
      status: 'ok',
      version: config.VERSION,
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    };
  });

  // Readiness probe - can the service accept traffic?
  server.get('/ready', async (_req: FastifyRequest, _reply: FastifyReply): Promise<ReadinessResponse> => {
    return {
      status: 'ready',
      checks: {
        self: { status: 'up', latencyMs: 0 },
      },
    };
  });
}
