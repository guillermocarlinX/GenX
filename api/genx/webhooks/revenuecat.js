// POST /api/genx/webhooks/revenuecat — subscriber lifecycle events.
//
// Hard rule: return 200 for every event successfully *recorded*, including
// ones not acted on. A non-2xx makes RevenueCat retry for days, and a 500 on
// an unknown event type turns one bad payload into an outage. Failures go in
// `process_error`, never in the HTTP status.

import { postgrest, env, supabaseUrl, readJson } from '../_shared.js';
import crypto from 'node:crypto';

const ACTION_TABLE = {
    INITIAL_PURCHASE: { status: 'active', entitlementsFromEvent: true, email: 'welcome' },
    RENEWAL: { status: 'active', entitlementsFromEvent: true, email: null },
    PRODUCT_CHANGE: { status: 'active', entitlementsFromEvent: true, email: null },
    UNCANCELLATION: { status: 'active', entitlementsFromEvent: true, email: null },
    CANCELLATION: { status: 'cancelled', entitlementsFromEvent: false, email: 'cancelled' },
    BILLING_ISSUE: { status: 'in_grace', entitlementsFromEvent: false, email: null },
    EXPIRATION: { status: 'expired', entitlementsFromEvent: false, entitlementsEmpty: true, email: 'expired' },
};

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    // 1. header mismatch or absent -> 401, nothing written
    const expected = env('REVENUECAT_WEBHOOK_AUTH_HEADER');
    const received = req.headers.authorization || '';
    const expectedBuf = Buffer.from(expected);
    const receivedBuf = Buffer.from(received);
    const headerOk = expectedBuf.length === receivedBuf.length && crypto.timingSafeEqual(expectedBuf, receivedBuf);
    if (!headerOk) return res.status(401).end();

    // 2. body not JSON, or a required field missing -> 422, nothing written
    let payload;
    try { payload = await readJson(req); } catch { return res.status(422).end(); }
    const event = payload?.event;
    if (!event || typeof event !== 'object' || !event.id || !event.type || !event.app_user_id) {
        return res.status(422).end();
    }

    const eventId = String(event.id);
    const eventType = String(event.type);
    const appUserId = String(event.app_user_id);
    const entitlementIds = Array.isArray(event.entitlement_ids) ? event.entitlement_ids : [];
    const productId = event.product_id ?? null;
    const store = event.store ?? null;
    const expirationAtMs = event.expiration_at_ms ?? null;
    const currentPeriodEnd = expirationAtMs ? new Date(Number(expirationAtMs)).toISOString() : null;

    // 3. insert into genx_webhook_events; a unique violation on event_id -> 200 deduplicated, no further work
    const insertResp = await postgrest('/genx_webhook_events', {
        method: 'POST',
        serviceRole: true,
        body: {
            event_id: eventId,
            event_type: eventType,
            app_user_id: appUserId,
            payload,
        },
    });
    if (insertResp.status === 409) {
        return res.status(200).json({ deduplicated: true });
    }
    if (!insertResp.ok) {
        // Could not even record the event — this is the one case where a 5xx
        // is honest (RevenueCat should retry, since nothing was recorded at all).
        return res.status(502).end();
    }

    // 4. app_user_id not a UUID or no auth.users row -> 200, process_error, no subscription write, no email
    const userExists = await authUserExists(appUserId);
    if (!userExists) {
        await postgrest(`/genx_webhook_events?event_id=eq.${eventId}`, {
            method: 'PATCH',
            serviceRole: true,
            body: { processed_at: new Date().toISOString(), process_error: 'unknown_app_user_id' },
        });
        return res.status(200).json({ ok: true });
    }

    const action = ACTION_TABLE[eventType] || null;
    let sendTemplate = null;

    if (action) {
        // 5. upsert exactly one genx_subscriptions row
        const subPatch = {
            user_id: appUserId,
            status: action.status,
            product_id: productId,
            store,
            source: 'revenuecat',
            current_period_end: currentPeriodEnd,
            last_event_id: eventId,
            updated_at: new Date().toISOString(),
        };
        if (action.entitlementsFromEvent) subPatch.entitlements = entitlementIds;
        if (action.entitlementsEmpty) subPatch.entitlements = [];

        const upsertResp = await postgrest('/genx_subscriptions?on_conflict=user_id', {
            method: 'POST',
            serviceRole: true,
            headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
            body: subPatch,
        });

        if (!upsertResp.ok) {
            await postgrest(`/genx_webhook_events?event_id=eq.${eventId}`, {
                method: 'PATCH',
                serviceRole: true,
                body: { processed_at: new Date().toISOString(), process_error: 'subscription_upsert_failed' },
            });
            return res.status(200).json({ ok: true });
        }

        sendTemplate = action.email;
    }

    // 6. at most one Brevo email, guarded by the genx_email_log unique constraint
    if (sendTemplate) {
        await sendTemplateEmailOnce({ userId: appUserId, template: sendTemplate, dedupeKey: eventId });
    }

    // 7. POST a summary to ZAPIER_GENX_HOOK_URL when set: 3s timeout, failures logged and swallowed
    await postToZapierIfConfigured({ eventId, eventType, appUserId, status: action?.status });

    // 8. set processed_at, return 200
    await postgrest(`/genx_webhook_events?event_id=eq.${eventId}`, {
        method: 'PATCH',
        serviceRole: true,
        body: { processed_at: new Date().toISOString() },
    });
    res.status(200).json({ ok: true });
}

async function authUserExists(userId) {
    const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRe.test(userId)) return false;
    try {
        const resp = await fetch(`${supabaseUrl()}/auth/v1/admin/users/${userId}`, {
            headers: {
                apikey: env('GENX_SUPABASE_SERVICE_ROLE_KEY'),
                Authorization: `Bearer ${env('GENX_SUPABASE_SERVICE_ROLE_KEY')}`,
            },
        });
        return resp.ok;
    } catch {
        return false;
    }
}

async function sendTemplateEmailOnce({ userId, template, dedupeKey }) {
    // The unique constraint on (user_id, template, dedupe_key) is the actual
    // idempotency mechanism — this insert is attempted first, and its result
    // decides whether an email is sent at all.
    const logResp = await postgrest('/genx_email_log', {
        method: 'POST',
        serviceRole: true,
        headers: { Prefer: 'return=representation' },
        body: { user_id: userId, template, dedupe_key: dedupeKey, status: 'sent' },
    });
    if (logResp.status === 409) return; // already sent for this event — skip silently

    const apiKey = process.env.BREVO_API_KEY;
    const templateId = process.env[`BREVO_TEMPLATE_${template.toUpperCase()}`];
    if (!apiKey || !templateId) return; // not configured — the log row above still records the attempt

    try {
        const userResp = await fetch(`${supabaseUrl()}/auth/v1/admin/users/${userId}`, {
            headers: {
                apikey: env('GENX_SUPABASE_SERVICE_ROLE_KEY'),
                Authorization: `Bearer ${env('GENX_SUPABASE_SERVICE_ROLE_KEY')}`,
            },
        });
        const user = userResp.ok ? await userResp.json() : null;
        const email = user?.email;
        if (!email) return;

        const sendResp = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': apiKey, 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: [{ email }], templateId: Number(templateId) }),
        });
        if (!sendResp.ok) {
            await postgrest(`/genx_email_log?user_id=eq.${userId}&template=eq.${template}&dedupe_key=eq.${dedupeKey}`, {
                method: 'PATCH',
                serviceRole: true,
                body: { status: 'failed', error: `brevo ${sendResp.status}` },
            });
        }
    } catch (e) {
        await postgrest(`/genx_email_log?user_id=eq.${userId}&template=eq.${template}&dedupe_key=eq.${dedupeKey}`, {
            method: 'PATCH',
            serviceRole: true,
            body: { status: 'failed', error: String(e.message || e) },
        });
    }
}

async function postToZapierIfConfigured(summary) {
    const url = process.env.ZAPIER_GENX_HOOK_URL;
    if (!url) return;
    const timeoutMs = Number(process.env.GENX_ZAPIER_TIMEOUT_MS || 3000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(summary),
            signal: controller.signal,
        });
    } catch (e) {
        console.error('[genx] zapier post failed:', e.message || e);
    } finally {
        clearTimeout(timer);
    }
}
