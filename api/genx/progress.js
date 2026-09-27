// GET /api/genx/progress — per-level completion counts for the caller.

import { ok, fail, requireUser, postgrest } from './_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return fail(res, 'VALIDATION_FAILED', 'GET only');

    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    const [levelsResp, workoutsResp, sessionsResp] = await Promise.all([
        postgrest('/genx_levels?is_published=eq.true&select=id,slug,title,sort_order&order=sort_order.asc', { token: auth.token }),
        postgrest('/genx_workouts?is_published=eq.true&select=id,level_id', { token: auth.token }),
        postgrest(`/genx_sessions?user_id=eq.${auth.userId}&status=eq.completed&select=workout_id`, { token: auth.token }),
    ]);

    if (!levelsResp.ok || !workoutsResp.ok || !sessionsResp.ok) {
        return fail(res, 'UPSTREAM_FAILED', 'could not read progress');
    }

    const levels = await levelsResp.json();
    const workouts = await workoutsResp.json();
    const completed = new Set((await sessionsResp.json()).map((s) => s.workout_id));

    const data = levels.map((level) => {
        const levelWorkouts = workouts.filter((w) => w.level_id === level.id);
        return {
            levelId: level.id,
            slug: level.slug,
            title: level.title,
            totalWorkouts: levelWorkouts.length,
            completedWorkouts: levelWorkouts.filter((w) => completed.has(w.id)).length,
        };
    });

    ok(res, data);
}
