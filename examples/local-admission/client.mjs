// SPDX-License-Identifier: Apache-2.0
// Real local challenge -> solve -> admission -> replay refusal.

import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { solveChallenge } from "../../javascript/src/maxwell.mjs";
import { DEMO_PATH, startDemoServer } from "./server.mjs";

// Node 18 may not expose Web Crypto globally; the SDK also runs in browsers.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

export function validateDemoUrl(input) {
    const url = new URL(input);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port ||
        url.username || url.password || url.pathname !== DEMO_PATH || url.search || url.hash) {
        throw new Error("demo only accepts an explicit 127.0.0.1 loopback endpoint");
    }
    return url.href;
}

export async function runDemo(input) {
    const url = validateDemoUrl(input);
    const post = (headers = {}) => fetch(url, {
        method: "POST", headers, redirect: "error", signal: AbortSignal.timeout(5000),
    });
    const first = await post();
    assert.equal(first.status, 401, "a fresh caller must receive the default challenge status");
    const { challenge } = await first.json();
    assert.equal(first.headers.get("x-maxwell-provider"), "viridis-security.com");
    assert.deepEqual(JSON.parse(first.headers.get("x-maxwell-challenge")), challenge);
    assert.ok(Number.isInteger(challenge.difficulty) && challenge.difficulty >= 1 &&
        challenge.difficulty <= 16, "keep demonstration work bounded");
    const now = Math.floor(Date.now() / 1000);
    assert.ok(challenge.expires_at > now && challenge.expires_at <= now + 60);
    const started = performance.now();
    const solution = await solveChallenge(challenge, { maxIterations: 32 * 2 ** challenge.difficulty });
    const solveMs = performance.now() - started;
    const headers = {
        "X-Maxwell-Challenge": JSON.stringify(challenge),
        "X-Maxwell-Solution": JSON.stringify(solution),
    };
    const accepted = await post(headers);
    assert.equal(accepted.status, 200, "a valid unused proof must reach the application");
    const body = await accepted.json();
    const replay = await post(headers);
    assert.equal(replay.status, 401, "a consumed proof must be refused");
    const replayBody = await replay.json();
    assert.equal(replayBody.error, "maxwell_replayed_solution");
    assert.notEqual(replayBody.challenge.server_nonce, challenge.server_nonce);
    return {
        demo: "local-http-admission",
        difficulty: challenge.difficulty,
        ttl_seconds: 60,
        challenge_status: first.status,
        accepted_status: accepted.status,
        replay_status: replay.status,
        replay_error: replayBody.error,
        application_calls: body.application_calls,
        client_solve_ms: solveMs,
        server_admission_ms: body.server_admission_ms,
        timing_scope: "One local run. Admission includes parsing, signature/work checks and nonce consumption; timings depend on hardware and runtime.",
    };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    if (process.argv.length !== 2) throw new Error("run without arguments; the demo creates its own loopback server");
    const demo = await startDemoServer();
    try {
        const receipt = await runDemo(demo.url);
        assert.equal(demo.getApplicationCalls(), 1);
        console.log(JSON.stringify(receipt, null, 2));
    } finally {
        await demo.close();
    }
}
