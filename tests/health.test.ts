import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../src/server.js';
import { FastifyInstance } from 'fastify';

describe('Health endpoints', () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await createServer();
    await server.ready();
  });

  afterAll(async () => {
    await server.close();
  });

  describe('GET /v1/health', () => {
    it('returns 200 with status ok', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/v1/health',
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.status).toBe('ok');
      expect(body.version).toBeDefined();
      expect(body.uptime).toBeGreaterThanOrEqual(0);
      expect(body.timestamp).toBeDefined();
    });

    it('returns valid ISO timestamp', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/v1/health',
      });

      const body = response.json();
      const date = new Date(body.timestamp);
      expect(date.toISOString()).toBe(body.timestamp);
    });
  });

  describe('GET /v1/ready', () => {
    it('returns 200 with ready status', async () => {
      const response = await server.inject({
        method: 'GET',
        url: '/v1/ready',
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.status).toBe('ready');
      expect(body.checks.self.status).toBe('up');
    });
  });
});
