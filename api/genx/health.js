// GET /api/genx/health — liveness + config. `?deep=1` also probes PostgREST
// and returns 503 if it is unreachable. Public: no auth required.

import { ok, fail, postgrest, env } from './_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return fail(res, 'VALIDATION_FAILED', 'GET only');

    const configured = ['GENX_SUPABASE_URL', 'GENX_SUPABASE_ANON_KEY', 'GENX_SUPABASE_SERVICE_ROLE_KEY']
        .every((name) => !!process.env[name]);

    if (req.query.deep !== '1') {
        return ok(res, { status: 'ok', configured });
    }

    try {
        const key = env('GENX_SUPABASE_ANON_KEY');
        const resp = await postgrest('/genx_levels?select=id&limit=1', { token: key });
        if (!resp.ok) {
            res.status(503).json({ ok: false, error: { code: 'UPSTREAM_FAILED', message: 'PostgREST unreachable' } });
            return;
        }
        ok(res, { status: 'ok', configured, postgrest: 'reachable' });
    } catch (e) {
        res.status(503).json({ ok: false, error: { code: 'UPSTREAM_FAILED', message: String(e.message || e) } });
    }
}
