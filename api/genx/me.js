// GET /api/genx/me — caller identity + entitlement state.

import { ok, fail, requireUser, postgrest } from './_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return fail(res, 'VALIDATION_FAILED', 'GET only');

    const auth = requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    const resp = await postgrest(`/genx_subscriptions?user_id=eq.${auth.userId}&select=*`, { token: auth.token });
    if (!resp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read subscription');
    const rows = await resp.json();
    const sub = rows[0] || null;

    ok(res, {
        userId: auth.userId,
        subscription: sub
            ? {
                  status: sub.status,
                  entitlements: sub.entitlements,
                  currentPeriodEnd: sub.current_period_end,
              }
            : { status: 'none', entitlements: [], currentPeriodEnd: null },
    });
}
