/**
 * CampusConnect — schema-aware migration & seed runner.
 *
 * Usage:
 *   node scripts/db.mjs migrate   # applies supabase/migrations/*.sql in order
 *   node scripts/db.mjs seed      # applies supabase/seed.sql (idempotent-ish)
 *
 * Connects via the Supavisor session pooler (works on IPv4-only networks):
 *   aws-1-ap-southeast-2.pooler.supabase.com:5432, user postgres.<project-ref>
 * Credentials come from .env: DB_PASSWORD (and SUPABASE_URL for the ref).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import 'dotenv/config';
import pg from 'pg';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SUPA_ROOT = path.resolve(__dirname, '..', '..', 'supabase');

const url = process.env.SUPABASE_URL;
const ref = url?.match(/https:\/\/([a-z0-9]+)\.supabase\.co/)?.[1];
const password = process.env.DB_PASSWORD;

if (!ref || !password) {
    console.error('Missing SUPABASE_URL or DB_PASSWORD in backend/.env');
    process.exit(1);
}

const client = new pg.Client({
    host: `aws-1-ap-southeast-2.pooler.supabase.com`,
    port: 5432,
    user: `postgres.${ref}`,
    database: 'postgres',
    password,
    ssl: { rejectUnauthorized: false },
});

await client.connect();
console.log(`Connected to Supabase Postgres (${ref}, ap-southeast-2 pooler)`);

// Track applied files so migrations can be re-run safely.
await client.query('create schema if not exists app');
await client.query(`create table if not exists app.schema_migrations (
    filename text primary key, applied_at timestamptz not null default now())`);

async function runFile(mode, file) {
    const label = path.relative(SUPA_ROOT, file);
    const { rows } = await client.query(
        'select 1 from app.schema_migrations where filename = $1', [label]);
    if (rows.length) { console.log(`= skip ${label} (already applied)`); return; }

    const sql = fs.readFileSync(file, 'utf8');
    try {
        await client.query('begin');
        await client.query(sql);
        await client.query('insert into app.schema_migrations (filename) values ($1)', [label]);
        await client.query('commit');
        console.log(`+ applied ${label}`);
    } catch (err) {
        await client.query('rollback');
        console.error(`x FAILED ${label}: ${err.message}`);
        throw err;
    }
}

const mode = process.argv[2];
if (mode === 'migrate') {
    const files = fs.readdirSync(path.join(SUPA_ROOT, 'migrations'))
        .filter(f => f.endsWith('.sql')).sort();
    for (const f of files) await runFile('migrate', path.join(SUPA_ROOT, 'migrations', f));
    console.log('All migrations applied.');
} else if (mode === 'seed') {
    await runFile('seed', path.join(SUPA_ROOT, 'seed.sql'));
    console.log('Seed complete.');
} else {
    console.error('Unknown mode. Use: migrate | seed');
    process.exit(1);
}

await client.end();
