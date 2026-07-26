# AskABD Identity Platform

Enterprise identity lifecycle, authentication, authorization, and security infrastructure.

## Quick Start

```bash
# Install dependencies
npm install

# Run in development
npm run dev

# Build
npm run build

# Test
npm test

# Start production
npm start
```

## Architecture

Single deployable TypeScript/Node.js service backed by PostgreSQL and Redis.

- **Framework:** Fastify 5
- **Language:** TypeScript 5.8 (strict mode)
- **Database:** PostgreSQL (identity, sessions, audit)
- **Cache/Counters:** Redis (rate limiting, lockout state)
- **Testing:** Vitest + fast-check (property-based)
- **Deployment:** Docker container

## API

All endpoints live under `/v1`. Health probes:

- `GET /v1/health` — liveness
- `GET /v1/ready` — readiness

## Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript to `dist/` |
| `npm test` | Run all tests (exits with status) |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run lint` | ESLint check |
| `npm run format:check` | Prettier check |
| `npm run typecheck` | TypeScript type validation |
| `npm run release:patch` | Bump patch version + git tag |
| `npm run release:minor` | Bump minor version + git tag |
| `npm run release:major` | Bump major version + git tag |

## Docker

```bash
docker build -t askabd-identity .
docker run -p 3100:3100 askabd-identity
```

## License

Proprietary — AskABD Technologies. All rights reserved.
