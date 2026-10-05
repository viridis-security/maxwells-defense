// SPDX-License-Identifier: Apache-2.0
// WP-4: HTTP modes, fetch interoperability, and response metadata.

import assert from "node:assert/strict";
import { fetchWithMaxwell } from "../src/maxwell.mjs";
import { issueChallenge, maxwellsDefense, verifySolution } from "../src/maxwell-express.mjs";

const secret = Buffer.alloc(32, "a");

async function challengeResponse(options = {}) {
    const middleware = maxwellsDefense({ serverSecret: secret, difficulty: 0, ...options });
    const res = {
        code: null, body: null, headers: new Map(),
        set(key, value) { this.headers.set(key.toLowerCase(), value); return this; },
        status(code) { this.code = code; return this; },
        json(body) { this.body = body; return this; },
    };
    await middleware({ originalUrl: "/api", headers: { host: "host" } }, res, () => {
        assert.fail("a request without a solution must not be forwarded");
    });
    return res;
}

const defaultResponse = await challengeResponse();
assert.equal(defaultResponse.code, 401);
assert.equal(defaultResponse.headers.has("retry-after"), false);
for (const retryAfterSeconds of [0, 7]) {
    const res = await challengeResponse({ challengeStatusCode: 429, retryAfterSeconds });
    assert.equal(res.code, 429);
    assert.equal(res.headers.get("retry-after"), String(retryAfterSeconds));
}
for (const options of [
    { challengeStatusCode: 403 }, { challengeStatusCode: "401" },
    { retryAfterSeconds: -1 }, { retryAfterSeconds: 1.5 }, { retryAfterSeconds: true },
]) {
    assert.throws(() => maxwellsDefense({ serverSecret: secret, ...options }));
}
console.log("[ok] default 401 and configurable 429 with Retry-After");

const originalFetch = globalThis.fetch;
const originalTimeout = globalThis.setTimeout;
const originalNow = Date.now;
try {
    for (const status of [401, 429]) {
        const challenge = issueChallenge({ serverSecret: secret, contextId: "host/api", difficulty: 0 });
        const first = new Response(JSON.stringify({ challenge }), {
            status, headers: { "X-Maxwell-Provider": "viridis-security.com", "Retry-After": "0" },
        });
        const success = new Response("ok");
        let calls = 0;
        globalThis.fetch = async (input, init) => {
            calls += 1;
            if (calls === 1) return first;
            assert.equal(init.headers.get("Authorization"), "fixture-only");
            const headers = init.headers;
            verifySolution({
                serverSecret: secret,
                challenge: JSON.parse(headers.get("X-Maxwell-Challenge")),
                solution: JSON.parse(headers.get("X-Maxwell-Solution")),
            });
            return success;
        };
        assert.equal(await fetchWithMaxwell("/api", { headers: { Authorization: "fixture-only" } }), success);
        assert.equal(calls, 2);
    }

    for (const [status, headers, body] of [
        [401, {}, { error: "authentication_required" }],
        [429, {}, { error: "rate_limited" }],
        [429, { "X-Maxwell-Provider": "viridis-security.com" }, { error: "no_challenge" }],
        [429, { "X-Maxwell-Provider": "viridis-security.com", "Retry-After": "Wed, 21 Oct 2037 07:28:00 GMT" },
            { challenge: defaultResponse.body.challenge }],
    ]) {
        const response = new Response(JSON.stringify(body), { status, headers });
        let calls = 0;
        globalThis.fetch = async () => { calls += 1; return response; };
        assert.equal(await fetchWithMaxwell("/api"), response);
        assert.equal(calls, 1);
        assert.deepEqual(await response.json(), body);
    }
    console.log("[ok] fetch solves Maxwell 401/429; ordinary auth/rate limits stay readable and unchanged");

    const waits = [];
    Date.now = () => 1_000_000;
    globalThis.setTimeout = (callback, delay) => { waits.push(delay); callback(); return 0; };
    let calls = 0;
    globalThis.fetch = async () => {
        calls += 1;
        return calls === 1 ? new Response(JSON.stringify({ challenge: defaultResponse.body.challenge }), {
            status: 429, headers: { "X-Maxwell-Provider": "viridis-security.com", "Retry-After": "1" },
        }) : new Response("ok");
    };
    await fetchWithMaxwell("/api");
    assert.deepEqual(waits, [1000]);
    assert.equal(calls, 2);
    console.log("[ok] fetch honors delta-seconds Retry-After before a single retry");
} finally {
    globalThis.fetch = originalFetch;
    globalThis.setTimeout = originalTimeout;
    Date.now = originalNow;
}
