// PATCH /api/genx/sessions/{sessionId} — updates status/watchedSeconds on the
// caller's own session row. See the evaluation order below; it is load-bearing,
// not incidental — do not reorder without re-reading why each check exists.

import { fail, requireUser, postgrest, readJson, isUuid } from '../_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'PATCH') return fail(res, 'VALIDATION_FAILED', 'PATCH only');

    // 1. no or unverifiable bearer token
    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    // 2. sessionId not a UUID
    const { sessionId } = req.query;
    if (!isUuid(sessionId)) return fail(res, 'VALIDATION_FAILED', 'sessionId must be a uuid');

    // 3. body is not an object, or carries neither status nor watchedSeconds
    let body;
    try { body = await readJson(req); } catch { return fail(res, 'VALIDATION_FAILED', 'invalid json body'); }
    if (typeof body !== 'object' || body === null || (body.status === undefined && body.watchedSeconds === undefined)) {
        return fail(res, 'VALIDATION_FAILED', 'body must carry status and/or watchedSeconds');
    }

    // 4. status present and not in completed/abandoned
    if (body.status !== undefined && !['completed', 'abandoned'].includes(body.status)) {
        return fail(res, 'VALIDATION_FAILED', 'status must be completed or abandoned');
    }

    // 5. watchedSeconds present and not an integer >= 0
    if (body.watchedSeconds !== undefined && !(Number.isInteger(body.watchedSeconds) && body.watchedSeconds >= 0)) {
        return fail(res, 'VALIDATION_FAILED', 'watchedSeconds must be an integer >= 0');
    }

    // Build the patch. user_id is never accepted from the body — the filter
    // below is what scopes this to the caller's own row, via RLS.
    const patch = {};
    if (body.watchedSeconds !== undefined) patch.watched_seconds = body.watchedSeconds;
    if (body.status === 'completed') { patch.status = 'completed'; patch.completed_at = new Date().toISOString(); }
    if (body.status === 'abandoned') { patch.status = 'abandoned'; patch.completed_at = null; }

    const resp = await postgrest(`/genx_sessions?id=eq.${sessionId}&user_id=eq.${auth.userId}`, {
        method: 'PATCH',
        token: auth.token,
        headers: { Prefer: 'return=representation' },
        body: patch,
    });

    if (!resp.ok) {
        // 7. PostgREST rejects the patch (constraint violation)
        return fail(res, 'UPSTREAM_FAILED', 'PostgREST rejected the patch');
    }

    const rows = await resp.json();
    // 6. the row does not exist, or belongs to another athlete — RLS/filter
    // make both cases return zero rows; report 404, never 403, so the handler
    // cannot leak whether the row exists for someone else.
    if (rows.length === 0) return fail(res, 'NOT_FOUND', 'session not found');

    const row = rows[0];
    res.status(200).json({
        ok: true,
        data: {
            id: row.id,
            workoutId: row.workout_id,
            status: row.status,
            startedAt: row.started_at,
            completedAt: row.completed_at,
            watchedSeconds: row.watched_seconds,
            client: row.client,
        },
    });
}
