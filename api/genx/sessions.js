// POST /api/genx/sessions — starts a session for the caller, returns 201.
// GET  /api/genx/sessions — caller's recent sessions, newest first, capped at 100.
//
// user_id always comes from the verified token, never from the request body.

import { ok, fail, requireUser, postgrest, readJson, isUuid } from './_shared.js';

const CLIENTS = ['web', 'ios', 'android'];

export default async function handler(req, res) {
    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    if (req.method === 'GET') {
        const resp = await postgrest(
            `/genx_sessions?user_id=eq.${auth.userId}&select=*&order=started_at.desc&limit=100`,
            { token: auth.token }
        );
        if (!resp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read sessions');
        const rows = await resp.json();
        return ok(res, rows.map(mapSession));
    }

    if (req.method === 'POST') {
        let body;
        try { body = await readJson(req); } catch { return fail(res, 'VALIDATION_FAILED', 'invalid json body'); }

        const { workoutId, client } = body || {};
        if (!isUuid(workoutId)) return fail(res, 'VALIDATION_FAILED', 'workoutId must be a uuid');
        if (!CLIENTS.includes(client)) return fail(res, 'VALIDATION_FAILED', 'client must be one of web/ios/android');

        const resp = await postgrest('/genx_sessions', {
            method: 'POST',
            token: auth.token,
            headers: { Prefer: 'return=representation' },
            body: { user_id: auth.userId, workout_id: workoutId, client, status: 'started' },
        });

        if (resp.status === 404 || resp.status === 403) {
            // RLS refused the insert (bad workout_id / restrict FK) — treat as not found.
            return fail(res, 'NOT_FOUND', 'workout not found');
        }
        if (!resp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not start session');
        const [row] = await resp.json();
        return ok(res, mapSession(row), 201);
    }

    fail(res, 'VALIDATION_FAILED', 'GET or POST only');
}

function mapSession(row) {
    return {
        id: row.id,
        workoutId: row.workout_id,
        status: row.status,
        startedAt: row.started_at,
        completedAt: row.completed_at,
        watchedSeconds: row.watched_seconds,
        client: row.client,
    };
}
