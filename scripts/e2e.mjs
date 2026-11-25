/**
 * CampusConnect — end-to-end API test against a RUNNING server.
 * Usage:  node scripts/e2e.mjs [baseUrl]
 * Default baseUrl: http://localhost:4000
 *
 * Read-only against the live database (no registrations created; the only
 * state-changing call asserted is a rejected/409 duplicate-registration path).
 */
const BASE = process.argv[2] ?? 'http://localhost:4000';
let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
    cond ? passed++ : failed++;
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
};

async function req(method, path, { token, body, form } = {}) {
    const res = await fetch(`${BASE}${path}`, {
        method,
        headers: {
            ...(form ? undefined : { 'Content-Type': 'application/json' }),
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        ...(form ? { body: form } : body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const data = await (res.headers.get('content-type')?.includes('json') ? res.json() : res.text());
    return { status: res.status, data };
}

console.log(`E2E against ${BASE}\n`);

// 1. health
{
    const r = await req('GET', '/api/health');
    ok('GET /api/health → 200 {status:"ok"}', r.status === 200 && r.data.status === 'ok',
       JSON.stringify(r.data));
}

// 2. student login (aaarav / Demo@1234 — seeded bcrypt hash)
{
    const r = await req('POST', '/api/auth/login',
        { body: { email: 'aarav@campus.edu', password: 'Demo@1234' } });
    ok('POST /api/auth/login (aarav) → 200 + JWT', r.status === 200 && !!r.data.token,
       r.data.user ? `${r.data.user.name} (${r.data.user.role})` : JSON.stringify(r.data));
    const token = r.data.token;

    // wrong password must 401
    const badLogin = await req('POST', '/api/auth/login',
        { body: { email: 'aarav@campus.edu', password: 'wrong' } });
    ok('POST /api/auth/login (wrong password) → 401', badLogin.status === 401);

    // 3. /api/auth/me carries the JWT contract
    const me = await req('GET', '/api/auth/me', { token });
    ok('GET /api/auth/me', me.status === 200 && !!me.data.user?.id && !!me.data.user?.department,
       JSON.stringify(me.data.user ?? me.data));

    // 4. approved-only public feed + search + category filter
    const feed = await req('GET', '/api/events');
    const allApproved = Array.isArray(feed.data) && feed.data.every(e => e.status === 'approved');
    ok('GET /api/events → approved events with club details',
       feed.status === 200 && allApproved && feed.data.length >= 2 && !!feed.data[0].club?.club_name,
       feed.data?.map?.(e => `${e.title} (${e.status}, ${e.club?.club_name})`).join(' | ') || JSON.stringify(feed.data));

    const search1 = await req('GET', '/api/events?search=Hackfest');
    ok('GET /api/events?search=Hackfest → matches', search1.status === 200
       && search1.data.length === 1 && /HackFest/i.test(search1.data[0].title));
    const search2 = await req('GET', '/api/events?category=Cultural');
    ok('GET /api/events?category=Cultural → only Cultural', search2.status === 200
       && search2.data.length >= 1 && search2.data.every(e => e.category === 'Cultural'));

    // 5. event detail
    const first = feed.data[0];
    const detail = await req('GET', `/api/events/${first.id}`);
    ok('GET /api/events/:id → 200 full detail', detail.status === 200 && detail.data.id === first.id);

    // 6. my-tickets (aarav has 1 seeded registration: HackFest)
    const mine = await req('GET', '/api/registrations/my-tickets', { token });
    ok('GET /api/registrations/my-tickets → 1 ticket with QR', mine.status === 200
       && mine.data.length === 1 && /^9f3e2b7c/.test(mine.data[0].qr_token)
       && mine.data[0].event?.title.includes('HackFest'),
       mine.data?.map?.(t => `${t.event?.title} qr=${t.qr_token} status=${t.status}`).join(' | ') || JSON.stringify(mine.data));

    // 7. student role guards: pending list & attendees forbidden, re-register 409
    const pendingAsStudent = await req('GET', '/api/events?status=pending', { token });
    ok('student cannot list pending events → 403', pendingAsStudent.status === 403);
    const dup = await req('POST', `/api/registrations/${first.id}`, { token });
    ok('duplicate registration → 409 (atomic RPC guard)', dup.status === 409
       && /already registered/i.test(dup.data.error ?? ''), dup.data.error ?? '');
}

// 8. professor review queue
{
    const r = await req('POST', '/api/auth/login',
        { body: { email: 'prof.sharma@campus.edu', password: 'Demo@1234' } });
    ok('POST /api/auth/login (prof.sharma) → 200 + JWT', r.status === 200 && r.data.user?.role === 'professor');
    const ptok = r.data.token;

    const pending = await req('GET', '/api/events?status=pending', { token: ptok });
    ok('professor sees pending review queue (Web3 workshop)', pending.status === 200
       && pending.data.some(e => e.title.includes('Web3') && e.status === 'pending'),
       pending.data?.map?.(e => `${e.title} [${e.status}] by ${e.creator?.name}`).join(' | ') || JSON.stringify(pending.data));

    const rejected = await req('GET', '/api/events?status=rejected', { token: ptok });
    ok('professor sees rejected queue (Rooftop DJ Night + note)', rejected.status === 200
       && rejected.data.some(e => e.title.includes('Rooftop') && e.rejection_note),
       rejected.data?.map?.(e => e.title).join(' | ') || JSON.stringify(rejected.data));

    // professor-only analytics
    const an = await req('GET', '/api/analytics/overview', { token: ptok });
    ok('GET /api/analytics/overview (professor)', an.status === 200
       && an.data.events?.total === 4 && an.data.registrations?.total === 3
       && !!an.data.category_distribution && !!an.data.department_turnout,
       JSON.stringify(an.data.events ?? an.data));

    // student token must NOT reach analytics
    const aarav = await req('POST', '/api/auth/login',
        { body: { email: 'aarav@campus.edu', password: 'Demo@1234' } });
    const denied = await req('GET', '/api/analytics/overview', { token: aarav.data.token });
    ok('student blocked from analytics → 403', denied.status === 403);
}

// 9. lost & found + feedback guards
{
    const lf = await req('GET', '/api/lost-found');
    ok('GET /api/lost-found (public)', lf.status === 200 && lf.data.length === 2,
       lf.data?.map?.(i => `${i.type}: ${i.item_name}`).join(' | ') || '');
    const aarav = await req('POST', '/api/auth/login',
        { body: { email: 'aarav@campus.edu', password: 'Demo@1234' } });
    const fb = await req('POST', '/api/events/not-a-uuid/feedback',
        { token: aarav.data.token, body: { rating: 5 } });
    ok('feedback without checked_in ticket → blocked (403/400)', fb.status === 403 || fb.status === 400,
       JSON.stringify(fb.data));
}

// 10. no-token guards
{
    const g = await req('GET', '/api/registrations/my-tickets');
    ok('no token on protected route → 401', g.status === 401);
    const corsProbe = await fetch(`${BASE}/api/health`, {
        headers: { Origin: 'http://localhost:5173' },
    });
    const allowOrigin = corsProbe.headers.get('access-control-allow-origin');
    ok('CORS allows configured Vite origin', allowOrigin === 'http://localhost:5173',
       `access-control-allow-origin=${allowOrigin}`);
}

console.log(`\n==== E2E: ${passed}/${passed + failed} PASSED ====`);
process.exit(failed ? 1 : 0);
