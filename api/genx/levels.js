// GET /api/genx/levels — published levels, ordered, each with workoutCount,
// completedCount (for the caller) and unlocked (per the caller's entitlement).

import { ok, fail, requireUser, postgrest, subscriptionCoversLevel } from './_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return fail(res, 'VALIDATION_FAILED', 'GET only');

    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    const [levelsResp, workoutsResp, sessionsResp, subResp] = await Promise.all([
        postgrest('/genx_levels?is_published=eq.true&select=*&order=sort_order.asc', { token: auth.token }),
        postgrest('/genx_workouts?is_published=eq.true&select=id,level_id', { token: auth.token }),
        postgrest(`/genx_sessions?user_id=eq.${auth.userId}&status=eq.completed&select=workout_id`, { token: auth.token }),
        postgrest(`/genx_subscriptions?user_id=eq.${auth.userId}&select=*`, { token: auth.token }),
    ]);

    if (!levelsResp.ok || !workoutsResp.ok || !sessionsResp.ok || !subResp.ok) {
        return fail(res, 'UPSTREAM_FAILED', 'could not read levels');
    }

    const levels = await levelsResp.json();
    const workouts = await workoutsResp.json();
    const completedSessions = await sessionsResp.json();
    const subRows = await subResp.json();
    const subscription = subRows[0] || null;

    const completedWorkoutIds = new Set(completedSessions.map((s) => s.workout_id));

    const data = levels.map((level) => {
        const levelWorkouts = workouts.filter((w) => w.level_id === level.id);
        const completedCount = levelWorkouts.filter((w) => completedWorkoutIds.has(w.id)).length;
        return {
            id: level.id,
            slug: level.slug,
            title: level.title,
            summary: level.summary,
            sortOrder: level.sort_order,
            requiredEntitlement: level.required_entitlement,
            coverImagePath: level.cover_image_path,
            workoutCount: levelWorkouts.length,
            completedCount,
            unlocked: subscriptionCoversLevel(subscription, level),
        };
    });

    ok(res, data);
}
