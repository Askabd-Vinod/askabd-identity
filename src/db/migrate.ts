import { readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { getPool, closePool } from './connection.js';

/**
 * Simple migration runner.
 * Reads .sql files from the migrations directory in order and executes them.
 * Tracks applied migrations in a migrations table.
 */
async function migrate(): Promise<void> {
  const pool = getPool();

  // Ensure migrations tracking table exists
  await pool.query(`
    CREATE TABLE IF NOT EXISTS _migrations (
      name VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Get already-applied migrations
  const { rows } = await pool.query<{ name: string }>('SELECT name FROM _migrations ORDER BY name');
  const applied = new Set(rows.map((r) => r.name));

  // Read migration files
  const migrationsDir = resolve(import.meta.dirname, 'migrations');
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  let count = 0;
  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = readFileSync(join(migrationsDir, file), 'utf-8');
    console.log(`Applying migration: ${file}`);
    await pool.query(sql);
    await pool.query('INSERT INTO _migrations (name) VALUES ($1)', [file]);
    count++;
  }

  if (count === 0) {
    console.log('No new migrations to apply.');
  } else {
    console.log(`Applied ${count} migration(s).`);
  }

  await closePool();
}

migrate().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
