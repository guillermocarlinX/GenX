// POST /api/genx/videos/{workoutId}/url — mints a 60s signed playback URL
// after the entitlement check. Body: { "client": "web"|"ios"|"android" }.
// Success 200: { ok:true, data:{ videoId, url, expiresInSeconds:60, durationSeconds } }.
//
// Side effect: exactly one genx_video_grants row on success, nothing on any
// failure path (including the 429, which must not extend its own window).
//
// genx_video_grants and genx_videos' storage_path are read/written with the
// service-role key here on purpose: this is one of the four service-role
// paths named in §8 of the blueprint (the rate-limit ledger has no client
// read policy by design, and signing needs Storage's own admin endpoint).

import { fail, ok, requireUser, postgrest, readJson, isUuid, supabaseUrl, env, subscriptionCoversLevel } from '../../_shared.js';

const CLIENTS = ['web', 'ios', 'android'];
const TTL_SECONDS = Number(process.env.GENX_SIGNED_URL_TTL_SECONDS || 60);
const GRANTS_PER_HOUR = Number(process.env.GENX_VIDEO_GRANTS_PER_HOUR || 60);
const BUCKET = process.env.GENX_STORAGE_BUCKET || 'genx-videos';

export default async function handler(req, res) {
    if (req.method !== 'POST') return fail(res, 'VALIDATION_FAILED', 'POST only');

    // 1. no or unverifiable bearer token
    const auth = await requireUser(req);
    if (!auth) return fail(res, 'UNAUTHENTICATED', 'missing or invalid token');

    // 2. workoutId not a UUID, or client missing or not in the enum
    const { workoutId } = req.query;
    let body;
    try { body = await readJson(req); } catch { return fail(res, 'VALIDATION_FAILED', 'invalid json body'); }
    const client = body?.client;
    if (!isUuid(workoutId)) return fail(res, 'VALIDATION_FAILED', 'workoutId must be a uuid');
    if (!CLIENTS.includes(client)) return fail(res, 'VALIDATION_FAILED', 'client must be one of web/ios/android');

    // 3. workout missing, unpublished, or its level unpublished (RLS filters this)
    const workoutResp = await postgrest(`/genx_workouts?id=eq.${workoutId}&select=*`, { token: auth.token });
    if (!workoutResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read workout');
    const [workout] = await workoutResp.json();
    if (!workout) return fail(res, 'NOT_FOUND', 'workout not found or not published');

    // 4. at least GENX_VIDEO_GRANTS_PER_HOUR grants in the last hour (service role: no client read policy on this table)
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const grantsResp = await postgrest(
        `/genx_video_grants?user_id=eq.${auth.userId}&granted_at=gte.${encodeURIComponent(oneHourAgo)}&select=id`,
        { serviceRole: true }
    );
    if (!grantsResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read grant history');
    const recentGrants = await grantsResp.json();
    if (recentGrants.length >= GRANTS_PER_HOUR) return fail(res, 'RATE_LIMITED', 'too many video URLs requested this hour');

    // 5. entitlement does not cover the workout's level
    const levelResp = await postgrest(`/genx_levels?id=eq.${workout.level_id}&select=*`, { token: auth.token });
    if (!levelResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read level');
    const [level] = await levelResp.json();
    if (!level) return fail(res, 'NOT_FOUND', 'level not found or not published');

    const subResp = await postgrest(`/genx_subscriptions?user_id=eq.${auth.userId}&select=*`, { token: auth.token });
    if (!subResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read subscription');
    const [subscription] = await subResp.json();
    if (!subscriptionCoversLevel(subscription, level)) {
        return fail(res, 'FORBIDDEN_NO_ENTITLEMENT', 'subscription does not cover this level');
    }

    // 6. entitled but no genx_videos row
    const videoResp = await postgrest(
        `/genx_videos?workout_id=eq.${workoutId}&select=*&order=sort_order.asc&limit=1`,
        { serviceRole: true }
    );
    if (!videoResp.ok) return fail(res, 'UPSTREAM_FAILED', 'could not read video');
    const [video] = await videoResp.json();
    if (!video) return fail(res, 'NOT_FOUND', 'no video for this workout');

    // 7. Storage refuses to sign
    let signed;
    try {
        const signResp = await fetch(`${supabaseUrl()}/storage/v1/object/sign/${BUCKET}/${video.storage_path}`, {
            method: 'POST',
            headers: {
                apikey: env('GENX_SUPABASE_SERVICE_ROLE_KEY'),
                Authorization: `Bearer ${env('GENX_SUPABASE_SERVICE_ROLE_KEY')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ expiresIn: TTL_SECONDS }),
        });
        if (!signResp.ok) return fail(res, 'UPSTREAM_FAILED', 'storage refused to sign');
        signed = await signResp.json();
    } catch (e) {
        return fail(res, 'UPSTREAM_FAILED', String(e.message || e));
    }

    // Side effect: exactly one grant row, only on this success path.
    await postgrest('/genx_video_grants', {
        method: 'POST',
        serviceRole: true,
        body: { user_id: auth.userId, video_id: video.id, client },
    });

    ok(res, {
        videoId: video.id,
        url: `${supabaseUrl()}/storage/v1${signed.signedURL}`,
        expiresInSeconds: TTL_SECONDS,
        durationSeconds: video.duration_seconds,
    });
}
