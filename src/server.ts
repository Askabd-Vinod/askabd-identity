import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { config } from './config/env.js';
import { healthRoutes } from './routes/health.js';

export async function createServer(): Promise<FastifyInstance> {
  const server = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      transport:
        config.NODE_ENV === 'development'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
    requestId: true,
  });

  // Security headers
  await server.register(helmet, { contentSecurityPolicy: false });

  // CORS
  await server.register(cors, {
    origin: config.CORS_ORIGINS,
    credentials: true,
  });

  // Routes
  await server.register(healthRoutes, { prefix: '/v1' });

  return server;
}
