// Shared helpers for every /api/genx/** endpoint.
//
// Vercel does not turn a file whose name begins with an underscore into a
// route, so this is a module, not an endpoint.
//
// Auth model: the caller sends `Authorization: Bearer <supabase access token>`.
// It is verified locally as HS256 against GENX_SUPABASE_JWT_SECRET — no network
// call to Supabase Auth on every request. The verified token is then forwarded
// as-is to PostgREST for every user-scoped read/write, so Postgres RLS is the
// actual enforcement, never this file's own logic. The service-role key is
// used only for the handful of paths that need it (webhook writes, minting a
// signed video URL) — see each endpoint for which.

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

export function env(name, { required = true } = {}) {
    const value = process.env[name];
    if (required && !value) throw new Error(`Missing required env var: ${name}`);
    return value;
}

export function supabaseUrl() {
    return env('GENX_SUPABASE_URL').replace(/\/$/, '');
}

// ---------------------------------------------------------------------------
// Response envelope — one shape, no exceptions.
// ---------------------------------------------------------------------------

export function ok(res, data, status = 200) {
    res.status(status).json({ ok: true, data });
}

export const ERROR_STATUS = {
    UNAUTHENTICATED: 401,
    FORBIDDEN_NO_ENTITLEMENT: 403,
    NOT_FOUND: 404,
    VALIDATION_FAILED: 422,
    RATE_LIMITED: 429,
    UPSTREAM_FAILED: 502,
    INTERNAL: 500,
};

export function fail(res, code, message) {
    const status = ERROR_STATUS[code] || 500;
    if (status >= 500) console.error(`[genx] ${code}: ${message}`);
    res.status(status).json({ ok: false, error: { code, message } });
}

// ---------------------------------------------------------------------------
// Auth — local HS256 verification, no dependency
// ---------------------------------------------------------------------------

function base64UrlDecode(input) {
    return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// Verifies a Supabase access token's signature and expiry against
// GENX_SUPABASE_JWT_SECRET. Returns the decoded payload (carries `sub`, the
// user id) or null if the token is missing, malformed, expired, or the
// signature does not match. Never throws.
export function verifyToken(bearerHeader) {
    if (!bearerHeader || !bearerHeader.startsWith('Bearer ')) return null;
    const token = bearerHeader.slice(7).trim();
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts;

    let payload;
    try {
        payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
    } catch {
        return null;
    }

    const secret = env('GENX_SUPABASE_JWT_SECRET');
    const expectedSig = crypto
        .createHmac('sha256', secret)
        .update(`${headerB64}.${payloadB64}`)
        .digest();
    const actualSig = base64UrlDecode(sigB64);
    if (expectedSig.length !== actualSig.length || !crypto.timingSafeEqual(expectedSig, actualSig)) {
        return null;
    }

    if (payload.aud !== 'authenticated') return null;
    if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) return null;
    if (!payload.sub) return null;

    return payload; // payload.sub is the user id
}

// Reads and verifies the caller's token from the request. Returns the user id
// (`sub`) and the raw token (to forward to PostgREST so RLS applies), or null.
export function requireUser(req) {
    const payload = verifyToken(req.headers.authorization);
    if (!payload) return null;
    return { userId: payload.sub, token: req.headers.authorization.slice(7).trim() };
}

// ---------------------------------------------------------------------------
// PostgREST — thin fetch wrapper. Pass the caller's own token so RLS decides;
// pass the service-role key only for the four paths that need to bypass RLS
// (documented at each call site).
// ---------------------------------------------------------------------------

export async function postgrest(path, { method = 'GET', token, serviceRole = false, body, headers = {} } = {}) {
    const key = serviceRole ? env('GENX_SUPABASE_SERVICE_ROLE_KEY') : env('GENX_SUPABASE_ANON_KEY');
    const authToken = serviceRole ? key : token;
    const resp = await fetch(`${supabaseUrl()}/rest/v1${path}`, {
        method,
        headers: {
            apikey: key,
            Authorization: `Bearer ${authToken}`,
            'Content-Type': 'application/json',
            ...headers,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return resp;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value) {
    return typeof value === 'string' && UUID_RE.test(value);
}

export async function readJson(req) {
    if (req.body && typeof req.body === 'object') return req.body;
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', (chunk) => { raw += chunk; });
        req.on('end', () => {
            if (!raw) return resolve({});
            try { resolve(JSON.parse(raw)); } catch { reject(new Error('invalid json')); }
        });
        req.on('error', reject);
    });
}

// ---------------------------------------------------------------------------
// Entitlement — the same rule the RLS policy in supabase/migrations/genx
// states at the database layer (genx_videos_read_entitled). Stated here only
// for the human-readable 403 vs 404 distinction the API makes; the actual
// enforcement is always the query itself, run with the caller's token.
// ---------------------------------------------------------------------------

export function subscriptionCoversLevel(subscription, level) {
    if (!subscription) return false;
    if (!['active', 'in_grace', 'cancelled'].includes(subscription.status)) return false;
    if (subscription.current_period_end && new Date(subscription.current_period_end) <= new Date()) return false;
    return (subscription.entitlements || []).includes(level.required_entitlement);
}
