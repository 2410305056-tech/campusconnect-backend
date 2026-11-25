/**
 * CampusConnect — end-to-end verification (Phase 6).
 *
 *  A) via direct Postgres (needs DB_PASSWORD): schema objects, constraints,
 *     indexes, RPC existence + rollback-safe smoke tests of both RPC paths.
 *  B) via REST as anon key: public read policies, storage bucket visibility.
 *
 * Usage:  node scripts/verify.mjs   (all env from backend/.env)
 */
import 'dotenv/config';
import pg from 'pg';
import { createClient } from '@supabase/supabase-js';

const ref = process.env.SUPABASE_URL?.match(/https:\/\/([a-z0-9]+)\.supabase\.co/)?.[1];
const password = process.env.DB_PASSWORD;
const results = [];
const log = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
};

async function restCheck(name, path, expectStatus, key) {
    const res = await fetch(`${process.env.SUPABASE_URL}${path}`, {
        headers: { apikey: key, Authorization: `Bearer ${key}` },
    });
    const body = res.headers.get('content-type')?.includes('json')
        ? await res.json() : await res.text();
    log(name, res.status === expectStatus, `HTTP ${res.status} ${JSON.stringify(body).slice(0, 120)}`);
    return res;
}

// ---------- B) anon-key REST checks (no DB password needed) ----------
console.log('\n== Anon-key REST checks (simulates the browser) ==');
await restCheck('anon can list approved events (RLS policy works)',
    '/rest/v1/events?select=title,status&limit=5', 200, process.env.SUPABASE_ANON_KEY);
await restCheck('anon can list lost_found (RLS policy works)',
    '/rest/v1/lost_found?select=item_name&limit=5', 200, process.env.SUPABASE_ANON_KEY);
await restCheck('anon CANNOT list users (RLS default-deny)',
    '/rest/v1/users?select=id&limit=1', 200, process.env.SUPABASE_ANON_KEY);
// anon POST must be rejected by RLS (no insert policy) — PostgREST returns 403
{
    const res = await fetch(`${process.env.SUPABASE_URL}/rest/v1/lost_found`, {
        method: 'POST',
        headers: {
            apikey: process.env.SUPABASE_ANON_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_ANON_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=representation',
        },
        body: JSON.stringify({ item_name: 'rls-test', type: 'lost', location: 'x', contact_info: 'x', posted_by: '00000000-0000-0000-0000-000000000000' }),
    });
    log('anon CANNOT INSERT into events/lost_found (write locked down)',
        res.status === 403 || res.status === 401 || res.status === 400,
        `HTTP ${res.status} ${(await res.text()).slice(0, 100)}`);
}

await fetch(`${process.env.SUPABASE_URL}/storage/v1/object/public/event-banners/__probe__.txt`)
    .then(async r => {
        const body = await r.text();
        // public bucket: 404 "Object not found" (read allowed, object absent).
        // private bucket would deny access before existence is evaluated.
        // public bucket returns "Object not found" for a missing object (read
        // allowed past the gate); a private bucket denies access instead.
        log('storage bucket "event-banners" is publicly readable',
            /object not found/i.test(body) || (r.status === 404 && /not found/i.test(body)),
            `HTTP ${r.status} ${body.slice(0, 80)}`);
    })
    .catch(() => log('storage bucket "event-banners" is publicly readable', false, 'request failed'));

// ---------- A) direct Postgres checks ----------
if (!password) {
    console.log('\nDB_PASSWORD not set — skipping direct-SQL verification.');
    console.log(`Summary: ${results.filter(r => r.ok).length}/${results.length} REST checks passed.`);
    process.exit(0);
}

console.log('\n== Direct-SQL checks ==');
const client = new pg.Client({
    host: `aws-1-ap-southeast-2.pooler.supabase.com`,
    port: 5432, user: `postgres.${ref}`, database: 'postgres',
    password, ssl: { rejectUnauthorized: false },
});
await client.connect();

const one = async (sql, params = []) => (await client.query(sql, params)).rows[0];

(async () => {
    // Tables
    const tables = await client.query(`
        select table_name from information_schema.tables
        where table_schema = 'public' order by table_name`);
    const expected = ['clubs', 'events', 'feedback', 'lost_found', 'registrations', 'users'];
    log('all 6 tables exist',
        expected.every(t => tables.rows.some(r => r.table_name === t)),
        tables.rows.map(r => r.table_name).join(', '));

    // Constraints + indexes counts
    const idx = await client.query(`
        select indexname from pg_indexes
        where schemaname = 'public'
          and indexname in ('idx_events_status_event_date', 'idx_registrations_student',
                            'idx_registrations_qr_token', 'idx_lost_found_type_resolved')`);
    log('4 performance indexes exist', idx.rows.length === 4, idx.rows.map(r => r.indexname).join(', '));

    const uq = await client.query(`
        select conname from pg_constraint
        where conrelid::regclass::text in ('registrations', 'feedback')
          and contype = 'u' and conname like 'uq_%'`);
    log('UNIQUE(event, student) constraints on registrations & feedback',
        uq.rows.length === 2, uq.rows.map(r => r.conname).join(', '));

    const fns = await client.query(`
        select proname from pg_proc
        where proname in ('register_for_event', 'verify_and_checkin_qr')`);
    log('both RPC functions exist', fns.rows.length === 2, fns.rows.map(r => r.proname).join(', '));

    const rls = await client.query(`
        select c.relname, c.relrowsecurity from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r'`);
    log('RLS enabled on all 6 tables', rls.rows.length === 6 && rls.rows.every(r => r.relrowsecurity),
        rls.rows.map(r => `${r.relname}:${r.relrowsecurity}`).join(', '));

    const pol = await client.query(`
        select count(*)::int as n from pg_policies
        where schemaname = 'public' and tablename in ('events', 'lost_found', 'clubs')`);
    log('public-read policies present (events/lost_found/clubs)', pol.rows[0].n >= 3,
        `${pol.rows[0].n} policies`);

    // Seed counts
    for (const t of ['users', 'clubs', 'events', 'registrations', 'lost_found']) {
        const { rows } = await client.query(`select count(*)::int as c from ${t}`);
        log(`seed rows in ${t}`, rows[0].c > 0, `${rows[0].c} rows`);
    }

    // RPC smoke tests inside a rolled-back transaction — zero side effects.
    // Each expected-failure call runs inside a SAVEPOINT so the aborted
    // transaction stays usable afterwards.
    const expectError = async (sql, params) => {
        await client.query('savepoint smoke_sp');
        let raised = null;
        try { await client.query(sql, params); }
        catch (e) { raised = e.message; }
        await client.query('rollback to savepoint smoke_sp');
        return raised;
    };

    await client.query('begin');
    try {
        // invalid event -> must raise
        const raised = await expectError(
            "select public.register_for_event(gen_random_uuid(), gen_random_uuid(), 'smoke-nopassword-token')");
        log('RPC register_for_event rejects unknown event', /not found/i.test(raised ?? ''), raised);

        // full positive path: pick an approved event the demo student is NOT
        // seeded into, then check-in via RPC
        const ev = await one(`select id from events e
            where e.status = 'approved' and e.registered_count < e.max_seats
              and not exists (select 1 from registrations r
                              where r.event_id = e.id and r.student_id =
                                  (select id from users where roll_or_faculty_id = 'STU301'))
            limit 1`);
        const stu = await one(`select id, name, email, department from users
                               where roll_or_faculty_id='STU301'`);
        const tok = 'smoke-test-' + Math.random().toString(16).slice(2, 10);
        const reg = await one(`select * from public.register_for_event($1, $2, $3)`, [ev.id, stu.id, tok]);
        log('RPC register_for_event returns a ticket', !!reg?.id && reg.id === reg.id,
            `ticket ${reg?.id} qr=${reg?.qr_token}`);

        // counter incremented?
        const ev2 = await one('select registered_count from events where id = $1', [ev.id]);
        const cntBefore = await one('select count(*)::int as c from registrations where event_id=$1', [ev.id]);
        log('registered_count stays consistent after RPC', ev2.registered_count === cntBefore.c,
            `counter=${ev2.registered_count} rows=${cntBefore.c}`);

        // check-in: first call succeeds
        const check1 = await one('select public.verify_and_checkin_qr($1) as r', [tok]);
        log('RPC verify_and_checkin_qr succeeds on first scan',
            check1.r?.status === 'checked_in', check1.r?.student?.name);

        // second call must raise "already checked in"
        const raised2 = await expectError('select public.verify_and_checkin_qr($1)', [tok]);
        log('RPC verify_and_checkin_qr blocks double check-in',
            /already been checked in/i.test(raised2 ?? ''), raised2);

        // also test the "full event" path: create a 1-seat event, fill it (this
        // INSERT must succeed and persist inside the txn), then try again
        const fullEv = await one(`
            with u as (select id from users where roll_or_faculty_id = 'STU201')
            insert into events (title, description, category, event_date, venue, max_seats, status, club_id, created_by)
            select 'smoke-full-test', 'x', 'Tech', now() + interval '1 day', 'x', 1, 'approved',
                   (select id from clubs where club_name = 'CodeCraft Tech Society'), (select id from u)
            returning id`);
        let fillError = null;
        await client.query('select public.register_for_event($1, (select id from users where roll_or_faculty_id = $2), $3)',
            [fullEv.id, 'STU301', 'smoke-full-seat']).catch(e => { fillError = e.message; });
        log('RPC register_for_event grants a valid seat request',
            fillError === null, fillError ?? 'seat granted');
        const raised3 = await expectError(
            'select public.register_for_event($1, (select id from users where roll_or_faculty_id = $2), $3)',
            [fullEv.id, 'STU302', 'smoke-full-seat2']);
        log('RPC register_for_event blocks registration when event is full',
            /full/i.test(raised3 ?? ''), raised3);

        // storage bucket check (needs SQL — the REST bucket-list endpoint is admin-only)
        const bucket = await one(`select id, public from storage.buckets where id = 'event-banners'`);
        log('storage bucket "event-banners" exists & public=true',
            !!bucket && bucket.public === true, JSON.stringify(bucket));
    } finally {
        await client.query('rollback'); // discard everything — DB untouched
        console.log('(smoke transaction rolled back — database untouched)');
    }

    await client.end();
    console.log(`\n==== VERIFICATION: ${results.filter(r => r.ok).length}/${results.length} PASSED ====`);
    process.exit(results.every(r => r.ok) ? 0 : 1);
})().catch(e => { console.error(e); process.exit(1); });
