import { createServer } from './server.js';
import { config } from './config/env.js';

async function main(): Promise<void> {
  const server = await createServer();

  try {
    await server.listen({ port: config.PORT, host: config.HOST });
    server.log.info(`Identity Platform v${config.VERSION} listening on ${config.HOST}:${config.PORT}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

main();
