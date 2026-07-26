import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { config } from './config/env.js';
import { healthRoutes } from './routes/health.js';
import { apiRoutes } from './routes/api-routes.js';

export async function createServer(): Promise<FastifyInstance> {
  const server = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      transport:
        config.NODE_ENV === 'development'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
    genReqId: () => crypto.randomUUID(),
  });

  await server.register(helmet, { contentSecurityPolicy: false });
  await server.register(cors, { origin: config.CORS_ORIGINS, credentials: true });
  await server.register(healthRoutes, { prefix: '/v1' });
  await server.register(apiRoutes, { prefix: '/v1' });

  return server;
}
