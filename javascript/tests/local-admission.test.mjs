// SPDX-License-Identifier: Apache-2.0
// MX-INV-6: actual loopback HTTP admission consumes each proof once.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { solveChallenge, _internal } from "../src/maxwell.mjs";
import { runDemo, validateDemoUrl } from "../../examples/local-admission/client.mjs";
import { createDemoServer, startDemoServer } from "../../examples/local-admission/server.mjs";

for (const difficulty of [0, 17, 1.5, "12"]) {
    assert.throws(() => createDemoServer({ difficulty }));
}
for (const url of [
    "https://127.0.0.1:1234/agent/invoke", "http://example.com:1234/agent/invoke",
    "http://localhost:1234/agent/invoke", "http://127.0.0.1/agent/invoke",
    "http://user:secret@127.0.0.1:1234/agent/invoke", "http://127.0.0.1:1234/agent/invoke?url=remote",
]) {
    assert.throws(() => validateDemoUrl(url));
}
console.log("[ok] local demo bounds difficulty and rejects remote destinations");

const demo = await startDemoServer({ difficulty: 8 });
const post = (headers = {}, body) => fetch(demo.url, {
    method: "POST", headers, body, redirect: "error", signal: AbortSignal.timeout(5000),
});
try {
    const receipt = await runDemo(demo.url);
    assert.equal(receipt.application_calls, 1);
    assert.equal(demo.getApplicationCalls(), 1);
    assert.ok(Number.isFinite(receipt.client_solve_ms) && receipt.client_solve_ms >= 0);
    assert.ok(Number.isFinite(receipt.server_admission_ms) && receipt.server_admission_ms >= 0);
    console.log("[ok] real HTTP challenge, actual SDK solve, first admission and replay refusal");

    const { challenge } = await (await post()).json();
    let invalidNonce = 0;
    let invalidHex;
    do {
        invalidHex = (++invalidNonce).toString(16).padStart(32, "0");
    } while (_internal.leadingZeroBits(createHash("sha256")
        .update(Buffer.from(challenge.server_nonce, "hex"))
        .update(Buffer.from(invalidHex, "hex")).digest()) >= challenge.difficulty);
    const challengeHeader = JSON.stringify(challenge);
    const invalid = await post({
        "X-Maxwell-Challenge": challengeHeader,
        "X-Maxwell-Solution": JSON.stringify({ solution_nonce: invalidHex }),
    });
    assert.equal(invalid.status, 401);
    assert.equal((await invalid.json()).error, "InsufficientWork");
    assert.equal(demo.getApplicationCalls(), 1);

    const solution = await solveChallenge(challenge);
    const headers = { "X-Maxwell-Challenge": challengeHeader, "X-Maxwell-Solution": JSON.stringify(solution) };
    const responses = await Promise.all(Array.from({ length: 8 }, () => post(headers)));
    assert.equal(responses.filter((response) => response.status === 200).length, 1);
    assert.equal(responses.filter((response) => response.status === 401).length, 7);
    for (const response of responses) {
        const body = await response.json();
        if (response.status === 401) assert.equal(body.error, "maxwell_replayed_solution");
    }
    assert.equal(demo.getApplicationCalls(), 2);
    console.log("[ok] invalid work never reaches handler; eight concurrent copies admit exactly once");

    assert.equal((await post({ "X-Maxwell-Challenge": "{" })).status, 401);
    assert.equal((await post({ "X-Maxwell-Challenge": "a".repeat(2049) })).status, 431);
    assert.equal((await post({}, "input is not executed")).status, 413);
    assert.equal((await fetch(demo.url)).status, 405);
    assert.equal(demo.getApplicationCalls(), 2);
    console.log("[ok] malformed headers, oversized headers, bodies and wrong methods cannot call handler");
} finally {
    await demo.close();
}
