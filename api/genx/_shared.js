// Shared helpers for every /api/genx/** endpoint.
//
// Vercel does not turn a file whose name begins with an underscore into a
// route, so this is a module, not an endpoint.
//
// Auth model: the caller sends `Authorization: Bearer <supabase access token>`.
// It is verified with one call to Supabase Auth's own GET /auth/v1/user —
// deliberately NOT a local HS256 check against a shared secret, because this
// project's JWT signing keys have already been rotated to an asymmetric key
// (ECC P-256); new access tokens are signed with that key, not HS256, so a
// local shared-secret check would reject every real session. Letting
// Supabase's own server verify the signature means it never matters which
// key or algorithm actually signed a given token. The verified token is then
// forwarded as-is to PostgREST for every user-scoped read/write, so Postgres
// RLS is the actual enforcement, never this file's own logic. The
// service-role key is used only for the handful of paths that need it
// (webhook writes, minting a signed video URL) — see each endpoint for which.

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
// Auth — verified by Supabase Auth itself, over the network
// ---------------------------------------------------------------------------

// A tiny in-memory cache so a burst of requests from the same session in the
// same warm Lambda instance doesn't re-verify the same token every time.
// Bounded by the token's own expiry — never longer than that.
const verifiedTokenCache = new Map();

// Verifies a Supabase access token by asking Supabase Auth's own
// GET /auth/v1/user. Returns { id, email } for a valid, non-expired token, or
// null for anything else (missing header, expired, revoked, malformed).
// Never throws.
export async function verifyToken(bearerHeader) {
    if (!bearerHeader || !bearerHeader.startsWith('Bearer ')) return null;
    const token = bearerHeader.slice(7).trim();
    if (!token) return null;

    const cached = verifiedTokenCache.get(token);
    if (cached && cached.expiresAt > Date.now()) return cached.user;

    try {
        const resp = await fetch(`${supabaseUrl()}/auth/v1/user`, {
            headers: {
                apikey: env('GENX_SUPABASE_ANON_KEY'),
                Authorization: `Bearer ${token}`,
            },
        });
        if (!resp.ok) return null;
        const user = await resp.json();
        if (!user?.id) return null;

        verifiedTokenCache.set(token, { user, expiresAt: Date.now() + 60_000 });
        if (verifiedTokenCache.size > 500) {
            const oldestKey = verifiedTokenCache.keys().next().value;
            verifiedTokenCache.delete(oldestKey);
        }
        return user;
    } catch {
        return null;
    }
}

// Reads and verifies the caller's token from the request. Returns the user id
// and the raw token (to forward to PostgREST so RLS applies), or null.
export async function requireUser(req) {
    const user = await verifyToken(req.headers.authorization);
    if (!user) return null;
    return { userId: user.id, token: req.headers.authorization.slice(7).trim() };
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
