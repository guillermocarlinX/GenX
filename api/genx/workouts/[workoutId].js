// GET /api/genx/workouts/{workoutId} — one published workout, plus video
// metadata (duration only — never a URL; see /videos/{workoutId}/url for
// that). Video metadata is only visible when RLS's entitlement policy lets
// the caller see the genx_videos row at all: an empty result there is not an
// error, it just means `video` is omitted from the response.

import { ok, fail, requireUser, postgrest, isUuid } from '../_shared.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return fail(res, 'VALIDATION_FAILED', 'GET only');

    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    const { workoutId } = req.query;
    if (!isUuid(workoutId)) return fail(res, 'VALIDATION_FAILED', 'workoutId must be a uuid');

    const workoutResp = await postgrest(`/genx_workouts?id=eq.${workoutId}&select=*`, { token: auth.token });
    if (!workoutResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read workout');
    const [workout] = await workoutResp.json();
    if (!workout) return fail(res, 'NOT_FOUND', 'workout not found or not published');

    const videoResp = await postgrest(
        `/genx_videos?workout_id=eq.${workoutId}&select=id,duration_seconds,sort_order&order=sort_order.asc`,
        { token: auth.token }
    );
    const videos = videoResp.ok ? await videoResp.json() : [];

    ok(res, {
        id: workout.id,
        levelId: workout.level_id,
        slug: workout.slug,
        title: workout.title,
        summary: workout.summary,
        sortOrder: workout.sort_order,
        durationMinutes: workout.duration_minutes,
        equipment: workout.equipment,
        coverImagePath: workout.cover_image_path,
        video: videos[0] ? { id: videos[0].id, durationSeconds: videos[0].duration_seconds } : null,
    });
}
