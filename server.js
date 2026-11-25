/**
 * CampusConnect API — Express + Supabase (server-side, service-role client)
 * Deploy target: Render (this file is the entry point: `npm start`).
 *
 * Security model:
 *  - The BROWSER only ever talks to this API (never to Supabase directly with
 *    privileged keys). RLS keeps direct anon-key access read-only and minimal.
 *  - This server uses SUPABASE_SECRET_KEY / SERVICE_ROLE, which bypasses RLS,
 *    and enforces role-based authorization itself.
 *  - Writes that need atomicity (event registration, QR check-in) go through
 *    Postgres RPCs for row-level locking (see supabase/migrations/0002_*).
 */
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const {
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
    SUPABASE_SERVICE_ROLE_KEY,
    JWT_SECRET,
    FRONTEND_URL,
    NODE_ENV,
    PORT = 4000,
} = process.env;

if (!SUPABASE_URL || !(SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY)) {
    console.error('FATAL: SUPABASE_URL and SUPABASE_SECRET_KEY (or SERVICE_ROLE) missing from .env');
    process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY ?? SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
});

const EVENT_CATEGORIES = ['Tech', 'Cultural', 'Sports', 'Workshop', 'Seminar'];
const STAFF = ['professor', 'club_head', 'admin'];
const BANNER_BUCKET = 'event-banners';
const BANNER_LIMIT = 5 * 1024 * 1024; // 5 MB

const corsOrigins = [
    'http://localhost:5173', // Vite dev server
    'http://127.0.0.1:5173',
    ...(FRONTEND_URL ? [FRONTEND_URL] : []),
];

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy
app.use(cors({
    origin(origin, cb) {
        // Allow same-origin/no-origin (curl, health checks) and whitelisted origins.
        if (!origin || corsOrigins.includes(origin)) return cb(null, true);
        return cb(null, false); // logged as 403 CORS rejection by the browser
    },
    credentials: false,
}));
app.use(express.json());

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: BANNER_LIMIT },
    fileFilter: (_req, file, cb) => {
        if (/^image\/(jpeg|png|webp)$/.test(file.mimetype)) return cb(null, true);
        cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'banner'));
    },
});

/* ----------------------------- auth helpers ----------------------------- */

function signSession(user) {
    // JWT contract: { id, email, role, name, department }
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role, name: user.name, department: user.department },
        JWT_SECRET,
        { expiresIn: '12h' },
    );
}

function requireAuth(...roles) {
    return (req, res, next) => {
        const header = req.headers.authorization ?? '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Missing bearer token' });
        let payload;
        try {
            payload = jwt.verify(token, JWT_SECRET);
        } catch {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        if (roles.length && !roles.includes(payload.role)) {
            return res.status(403).json({ error: `Requires role: ${roles.join(' / ')}` });
        }
        req.user = payload;
        req.userId = payload.id;
        next();
    };
}

/** The club owned by the logged-in club_head (null-safe). */
async function clubOf(userId) {
    const { data, error } = await supabase
        .from('clubs').select('id, club_name').eq('head_id', userId).maybeSingle();
    if (error) throw error;
    return data;
}

const bad = (res, code, error) => res.status(code).json({ error });

/* --------------------------------- auth --------------------------------- */

app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role = 'student', department, roll_or_faculty_id } = req.body ?? {};
    if (!name || !email || !password || !department || !roll_or_faculty_id) {
        return bad(res, 400, 'name, email, password, department, roll_or_faculty_id are required');
    }
    const { data, error } = await supabase
        .from('users')
        .insert({
            name, email, department, roll_or_faculty_id, role,
            password_hash: bcrypt.hashSync(password, 10),
        })
        .select('id, name, email, role, department, roll_or_faculty_id')
        .single();
    if (error) return bad(res, error.code === '23505' ? 409 : 400, error.message);
    res.status(201).json({ user: data, token: signSession(data) });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body ?? {};
    if (!email || !password) return bad(res, 400, 'email and password required');
    const { data: user, error } = await supabase
        .from('users').select('*').eq('email', email).maybeSingle();
    if (error || !user || !bcrypt.compareSync(password, user.password_hash)) {
        return bad(res, 401, 'Invalid credentials');
    }
    const safe = { id: user.id, name: user.name, email: user.email, role: user.role,
                   department: user.department, roll_or_faculty_id: user.roll_or_faculty_id };
    res.json({ user: safe, token: signSession(safe) });
});

app.get('/api/auth/me', requireAuth(), (req, res) => {
    res.json({ user: { id: req.user.id, email: req.user.email, role: req.user.role,
                        name: req.user.name, department: req.user.department } });
});

/* -------------------------------- events -------------------------------- */

/**
 * Event feed. Query params:
 *   search   — case-insensitive match on title/description
 *   category — one of EVENT_CATEGORIES
 *   status   — 'pending' | 'rejected' | 'approved' | 'all'
 *              pending/rejected/all REQUIRE a staff JWT; default is 'approved'.
 */
app.get('/api/events', async (req, res) => {
    const STATUS_UNSAFE = { pending: 1, rejected: 1, all: 1 };
    const { status, search, category } = req.query;

    if (STATUS_UNSAFE[status]) {
        // needs a valid staff JWT; for club_head, scope to their own club
        const header = req.headers.authorization ?? '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!token) return bad(res, 401, 'Login required to view pending/rejected events');
        let user;
        try { user = jwt.verify(token, JWT_SECRET); } catch {
            return bad(res, 401, 'Invalid or expired token');
        }
        if (!STAFF.includes(user.role)) return bad(res, 403, `Requires role: ${STAFF.join(' / ')}`);

        let query = supabase
            .from('events')
            .select('*, club:club_id (id, club_name, category), creator:created_by (name, email)')
            .order('created_at', { ascending: false });
        if (status !== 'all') query = query.eq('status', status);
        if (user.role === 'club_head') {
            const club = await clubOf(user.id);
            query = query.eq('club_id', club?.id ?? '00000000-0000-0000-0000-000000000000');
        }
        const { data, error } = await query;
        if (error) return bad(res, 400, error.message);
        return res.json(data);
    }

    let query = supabase
        .from('events')
        .select('*, club:club_id (id, club_name, category)')
        .eq('status', 'approved')
        .order('event_date', { ascending: true });
    if (search) query = query.or(`title.ilike.%${search}%,description.ilike.%${search}%`);
    if (category) query = query.eq('category', category);
    const { data, error } = await query;
    if (error) return bad(res, 400, error.message);
    res.json(data);
});

app.get('/api/events/:id', async (req, res) => {
    const { data: event, error } = await supabase
        .from('events')
        .select('*, club:club_id (id, club_name, category), creator:created_by (name, email)')
        .eq('id', req.params.id)
        .maybeSingle();
    if (error) return bad(res, 400, error.message);
    if (!event) return bad(res, 404, 'Event not found');
    res.json(event);
});

/**
 * Create an event proposal (status 'pending'). Accepts multipart/form-data
 * with an optional `banner` image (jpeg/png/webp, <5 MB) or JSON with a
 * pre-hosted `banner_url`.
 */
app.post('/api/events', requireAuth('club_head', 'admin'), upload.single('banner'), async (req, res) => {
    const body = req.body ?? {};
    const { title, description, category, event_date, venue } = body;
    const max_seats = Number(body.max_seats);
    if (!title || !description || !event_date || !venue) {
        return bad(res, 400, 'title, description, event_date, venue are required');
    }
    if (!EVENT_CATEGORIES.includes(category)) {
        return bad(res, 400, `category must be one of: ${EVENT_CATEGORIES.join(', ')}`);
    }
    if (!Number.isInteger(max_seats) || max_seats <= 0) {
        return bad(res, 400, 'max_seats must be a positive integer');
    }
    if (Number.isNaN(new Date(event_date).getTime())) {
        return bad(res, 400, 'event_date must be a valid date');
    }

    let clubId = body.club_id;
    if (req.user.role === 'club_head') {
        const club = await clubOf(req.user.id);
        if (!club) return bad(res, 400, 'You are not assigned as head of any club');
        clubId = club.id;
    }
    if (!clubId) return bad(res, 400, 'club_id is required (admin creating for a club)');

    // Banner upload to the public event-banners bucket
    let banner_url = body.banner_url ?? null;
    if (req.file) {
        const safeName = req.file.originalname.replace(/[^\w.\-]+/g, '_');
        const objectPath = `${clubId}/${Date.now()}-${safeName}`;
        const { error: upErr } = await supabase.storage
            .from(BANNER_BUCKET)
            .upload(objectPath, req.file.buffer, { contentType: req.file.mimetype });
        if (upErr) return bad(res, 500, `Banner upload failed: ${upErr.message}`);
        banner_url = supabase.storage.from(BANNER_BUCKET).getPublicUrl(objectPath).data.publicUrl;
    }

    const { data, error } = await supabase
        .from('events')
        .insert({ title, description, category, event_date, venue, max_seats,
                  banner_url, club_id: clubId, created_by: req.user.id, status: 'pending' })
        .select('*, club:club_id (id, club_name)')
        .single();
    if (error) return bad(res, 400, error.message);
    res.status(201).json(data);
});

/**
 * Review queue action (professor / admin):
 *   PATCH /api/events/:id/review  { "action": "approve" } |
 *                                 { "action": "reject", "rejection_note": "..." }
 * Approval refuses same-venue, same-calendar-day clashes with an approved event.
 */
app.patch('/api/events/:id/review', requireAuth('professor', 'admin'), async (req, res) => {
    const { action, rejection_note } = req.body ?? {};
    const { data: event } = await supabase
        .from('events').select('*').eq('id', req.params.id).maybeSingle();
    if (!event) return bad(res, 404, 'Event not found');
    if (event.status !== 'pending') return bad(res, 409, `Event is already ${event.status}`);

    if (action === 'approve') {
        // Venue clash: another approved event at the same venue on the same calendar day.
        const from = new Date(event.event_date);
        from.setHours(0, 0, 0, 0);
        const to = new Date(from);
        to.setDate(to.getDate() + 1);
        const { data: clashes } = await supabase
            .from('events')
            .select('id, title, venue, event_date')
            .eq('status', 'approved')
            .eq('venue', event.venue)
            .neq('id', event.id)
            .gte('event_date', from.toISOString())
            .lt('event_date', to.toISOString());
        if (clashes?.length) {
            return res.status(409).json({
                error: `Venue "${event.venue}" is already booked on ${from.toISOString().slice(0, 10)} — resolve the clash before approving.`,
                conflicting_events: clashes,
            });
        }
        const { data, error } = await supabase
            .from('events')
            .update({ status: 'approved', approved_by: req.user.id, rejection_note: null })
            .eq('id', event.id).select('*').single();
        if (error) return bad(res, 400, error.message);
        return res.json(data);
    }

    if (action === 'reject') {
        if (!rejection_note) return bad(res, 400, 'rejection_note is required when rejecting');
        const { data, error } = await supabase
            .from('events')
            .update({ status: 'rejected', approved_by: req.user.id, rejection_note })
            .eq('id', event.id).select('*').single();
        if (error) return bad(res, 400, error.message);
        return res.json(data);
    }

    return bad(res, 400, 'action must be "approve" or "reject"');
});

/* --------------------- registration & QR check-in (RPC) ------------------- */

/**
 * Student registers for an event. Delegates to the atomic Postgres RPC
 * `register_for_event` (FOR UPDATE row lock → overbooking is impossible)
 * and returns the generated QR ticket.
 */
app.post('/api/registrations/:eventId', requireAuth('student'), async (req, res) => {
    const qrToken = crypto.randomUUID().replaceAll('-', '');
    const { data, error } = await supabase.rpc('register_for_event', {
        p_event_id: req.params.eventId,
        p_student_id: req.user.id,
        p_qr_token: qrToken,
    });
    if (error) return bad(res, 409, error.message);
    res.status(201).json({ registration: data, qr_token: qrToken });
});

app.get('/api/registrations/my-tickets', requireAuth('student', 'club_head', 'admin'), async (req, res) => {
    const { data, error } = await supabase
        .from('registrations')
        .select('id, qr_token, status, registered_at, event:event_id (id, title, category, event_date, venue, status, banner_url, club:club_id (club_name))')
        .eq('student_id', req.user.id)
        .order('registered_at', { ascending: false });
    if (error) return bad(res, 400, error.message);
    res.json(data);
});

app.get('/api/registrations/event/:eventId/attendees', requireAuth(...STAFF), async (req, res) => {
    const { data: event } = await supabase
        .from('events').select('id, club_id, title').eq('id', req.params.eventId).maybeSingle();
    if (!event) return bad(res, 404, 'Event not found');
    if (req.user.role === 'club_head') {
        const club = await clubOf(req.user.id);
        if (club?.id !== event.club_id) return bad(res, 403, 'You can only view attendees of your own club\'s events');
    }
    const { data, error } = await supabase
        .from('registrations')
        .select('id, qr_token, status, registered_at, student:student_id (name, email, roll_or_faculty_id, department)')
        .eq('event_id', event.id)
        .order('registered_at');
    if (error) return bad(res, 400, error.message);
    res.json({ event: event, attendees: data, total: data.length });
});

/** Gate check-in — atomic RPC, exactly-once per ticket. */
app.post('/api/registrations/verify-qr', requireAuth(...STAFF), async (req, res) => {
    const { qr_token } = req.body ?? {};
    if (!qr_token) return bad(res, 400, 'qr_token required');
    const { data, error } = await supabase.rpc('verify_and_checkin_qr', { p_qr_token: qr_token });
    if (error) return bad(res, 409, error.message);
    res.json(data);
});

/* ------------------------------- analytics -------------------------------- */

app.get('/api/analytics/overview', requireAuth(...STAFF), async (_req, res) => {
    const [events, registrations, users] = await Promise.all([
        supabase.from('events').select('id, category, status, registered_count, max_seats'),
        supabase.from('registrations').select('id, status, student_id'),
        supabase.from('users').select('id, department'),
    ]);
    if (events.error) return bad(res, 400, events.error.message);
    if (registrations.error) return bad(res, 400, registrations.error.message);
    if (users.error) return bad(res, 400, users.error.message);

    const regList = registrations.data;
    const checkedIn = regList.filter(r => r.status === 'checked_in').length;
    const deptById = Object.fromEntries(users.data.map(u => [u.id, u.department]));

    const categoryDistribution = {};
    for (const e of events.data) categoryDistribution[e.category] = (categoryDistribution[e.category] ?? 0) + 1;

    const departmentTurnout = {};
    const deptUsers = {};
    for (const r of regList) {
        const dept = deptById[r.student_id] ?? 'Unknown';
        departmentTurnout[dept] = (departmentTurnout[dept] ?? 0) + 1;
    }
    for (const u of users.data) deptUsers[u.department] = (deptUsers[u.department] ?? 0) + 1;

    res.json({
        events: {
            total: events.data.length,
            approved: events.data.filter(e => e.status === 'approved').length,
            pending: events.data.filter(e => e.status === 'pending').length,
            seats_capacity: events.data.reduce((s, e) => s + e.max_seats, 0),
            seats_filled: events.data.reduce((s, e) => s + e.registered_count, 0),
        },
        registrations: {
            total: regList.length,
            checked_in: checkedIn,
            check_in_percentage: regList.length
                ? Math.round((checkedIn / regList.length) * 1000) / 10 : 0,
        },
        category_distribution: categoryDistribution,
        department_turnout: departmentTurnout, // registrations per department
        student_count_by_department: deptUsers,
    });
});

/* -------------------------------- feedback -------------------------------- */

/** Students only, and only for events they actually checked into. */
app.post('/api/events/:eventId/feedback', requireAuth('student'), async (req, res) => {
    const rating = Number(req.body?.rating);
    const comment = req.body?.comment ?? null;
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
        return bad(res, 400, 'rating must be an integer between 1 and 5');
    }
    const { data: ticket } = await supabase
        .from('registrations')
        .select('id, status')
        .eq('event_id', req.params.eventId)
        .eq('student_id', req.user.id)
        .maybeSingle();
    if (!ticket) return bad(res, 403, 'You are not registered for this event');
    if (ticket.status !== 'checked_in') return bad(res, 403, 'You can only review events you checked in to');
    const { data, error } = await supabase
        .from('feedback')
        .upsert({ event_id: req.params.eventId, student_id: req.user.id, rating, comment },
                { onConflict: 'event_id,student_id' })
        .select('*').single();
    if (error) return bad(res, 400, error.message);
    res.status(201).json(data);
});

app.get('/api/events/:eventId/feedback', requireAuth(...STAFF), async (req, res) => {
    const { data, error } = await supabase
        .from('feedback')
        .select('*, student:student_id (name, department)')
        .eq('event_id', req.params.eventId)
        .order('created_at');
    if (error) return bad(res, 400, error.message);
    res.json(data);
});

/* ------------------------------- lost & found ----------------------------- */

app.get('/api/lost-found', async (_req, res) => {
    const { data, error } = await supabase
        .from('lost_found')
        .select('*, poster:posted_by (name, department)')
        .order('created_at', { ascending: false });
    if (error) return bad(res, 400, error.message);
    res.json(data);
});

app.post('/api/lost-found', requireAuth(...STAFF), async (req, res) => {
    const { item_name, type, description, location, contact_info, image_url } = req.body ?? {};
    if (!item_name || !type || !location || !contact_info) {
        return bad(res, 400, 'item_name, type, location, contact_info are required');
    }
    if (!['lost', 'found'].includes(type)) return bad(res, 400, 'type must be "lost" or "found"');
    const { data, error } = await supabase
        .from('lost_found')
        .insert({ item_name, type, description, location, contact_info, image_url,
                  posted_by: req.user.id })
        .select('*').single();
    if (error) return bad(res, 400, error.message);
    res.status(201).json(data);
});

// Mark resolved — by the poster or an admin.
app.patch('/api/lost-found/:id/resolve', requireAuth('student', 'club_head', 'professor', 'admin'), async (req, res) => {
    const { data: item } = await supabase
        .from('lost_found').select('id, posted_by, is_resolved').eq('id', req.params.id).maybeSingle();
    if (!item) return bad(res, 404, 'Lost & found post not found');
    if (req.user.role !== 'admin' && item.posted_by !== req.user.id) {
        return bad(res, 403, 'Only the poster or an admin can resolve this post');
    }
    const { data, error } = await supabase
        .from('lost_found')
        .update({ is_resolved: true })
        .eq('id', item.id).select('*').single();
    if (error) return bad(res, 400, error.message);
    res.json(data);
});

/* --------------------------------- misc ----------------------------------- */

// Render health check
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date() });
});

app.get('/', (_req, res) => {
    res.json({ service: 'campusconnect-api', docs: 'see /api/health and the README' });
});

/* ------------------------------ boot & shutdown ---------------------------- */

const isProd = NODE_ENV === 'production';

app.use((err, _req, res, next) => {
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: `Upload rejected: ${err.message}` });
    }
    console.error(err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => {
    console.log(`CampusConnect API listening on http://localhost:${PORT} (env: ${isProd ? 'production' : 'development'})`);
});

// Clean shutdown for Render deploys
function shutdown(signal) {
    console.log(`${signal} received — shutting down gracefully...`);
    server.close(() => {
        console.log('HTTP server closed. Bye.');
        process.exit(0);
    });
    // force-exit if connections linger
    setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
