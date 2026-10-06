// SPDX-License-Identifier: Apache-2.0
// WP-3: transport-only identity and bounded adaptive failure signals.

import assert from "node:assert/strict";
import {
    FailedAttemptDifficultyOracle, FailedAttemptHistory,
    NonceStoreUnavailable, maxwellsDefense,
} from "../src/maxwell-express.mjs";
import { solveChallenge } from "../src/maxwell.mjs";

const secret = Buffer.alloc(32, "s");

function harness(options = {}) {
    const seen = [];
    let forwarded = 0;
    let appError;
    const middleware = maxwellsDefense({
        serverSecret: secret,
        difficultyOracle(req, signals) {
            assert.equal(Object.isFrozen(signals), true);
            seen.push({ ...signals });
            return 0;
        },
        ...options,
    });
    return {
        seen,
        get forwarded() { return forwarded; },
        set appError(error) { appError = error; },
        async request({ peer = "192.0.2.1", path = "/api", headers = {} } = {}) {
            const req = {
                socket: peer === null ? undefined : { remoteAddress: peer },
                ip: "spoofed-by-express-trust-proxy", // never used
                method: "POST", originalUrl: path, headers: { host: "example.test", ...headers },
            };
            const res = {
                body: undefined,
                set() { return this; }, status() { return this; },
                json(body) { this.body = body; return this; },
            };
            await middleware(req, res, (error) => {
                if (error) throw error;
                forwarded += 1;
                if (appError) throw appError;
                res.body = { ok: true };
            });
            return res.body;
        },
    };
}

async function solvedHeaders(body) {
    return {
        "x-maxwell-challenge": JSON.stringify(body.challenge),
        "x-maxwell-solution": JSON.stringify(await solveChallenge(body.challenge)),
    };
}

const history = new FailedAttemptHistory();
const defaults = harness({ failureHistory: history });
const initial = await defaults.request({ headers: {
    forwarded: "for=198.51.100.9", "x-forwarded-for": "198.51.100.8",
} });
assert.equal(initial.challenge.context_id, "example.test/api");
assert.deepEqual(defaults.seen.at(-1), {
    remote_addr: "192.0.2.1", method: "POST", path: "/api",
    failed_attempts: 0, history_saturated: false,
});
assert.equal(history.entries.size, 0);
await defaults.request({ peer: null });
assert.equal(defaults.seen.at(-1).remote_addr, null);
console.log("[ok] default binding preserved; raw socket peer overrides spoofed proxy headers/req.ip");

const bound = harness({ contextFactory(req, signals) {
    assert.equal(Object.isFrozen(signals), true);
    return req.headers.host + req.originalUrl + "|" + signals.remote_addr;
} });
const boundHeaders = await solvedHeaders(await bound.request());
const crossPeer = await bound.request({ peer: "192.0.2.2", headers: {
    ...boundHeaders, "x-forwarded-for": "192.0.2.1",
} });
assert.equal(crossPeer.error, "InvalidSolution: context mismatch");
assert.equal(bound.seen.at(-1).failed_attempts, 1);
assert.deepEqual(await bound.request({ headers: boundHeaders }), { ok: true });
await bound.request();
assert.equal(bound.seen.at(-1).failed_attempts, 0);
assert.equal(bound.forwarded, 1);
console.log("[ok] optional peer binding rejects another peer without consuming original nonce");

const attempts = harness();
const malformed = await attempts.request({ headers: { "x-maxwell-solution": "{" } });
assert.equal(attempts.seen.at(-1).failed_attempts, 1);
const valid = await solvedHeaders(malformed);
assert.deepEqual(await attempts.request({ headers: valid }), { ok: true });
const replay = await attempts.request({ headers: valid });
assert.equal(replay.error, "maxwell_replayed_solution");
assert.equal(attempts.seen.at(-1).failed_attempts, 2);
await attempts.request({ headers: { forwarded: "for=other-peer" } });
assert.equal(attempts.seen.at(-1).failed_attempts, 2);
await attempts.request({ peer: "192.0.2.2" });
assert.equal(attempts.seen.at(-1).failed_attempts, 0);
await attempts.request({ path: "/other" });
assert.equal(attempts.seen.at(-1).failed_attempts, 0);
for (const headers of [
    { "x-maxwell-challenge": "", "x-maxwell-solution": "" },
    { "x-maxwell-challenge": "null", "x-maxwell-solution": "null" },
    { "x-maxwell-challenge": "[]", "x-maxwell-solution": "{}" },
    { "x-maxwell-challenge": "{", "x-maxwell-solution": "{}" },
]) {
    const bad = harness();
    await bad.request({ headers });
    assert.equal(bad.seen.at(-1).failed_attempts, 1);
    assert.equal(bad.forwarded, 0);
}
const signatures = harness();
const sigHeaders = await solvedHeaders(await signatures.request());
const badChallenge = JSON.parse(sigHeaders["x-maxwell-challenge"]);
badChallenge.hmac_sig = "00".repeat(32);
assert.equal((await signatures.request({ headers: {
    ...sigHeaders, "x-maxwell-challenge": JSON.stringify(badChallenge),
} })).error, "SignatureMismatch");
assert.equal(signatures.seen.at(-1).failed_attempts, 1);
assert.deepEqual(await signatures.request({ headers: sigHeaders }), { ok: true });
console.log("[ok] malformed/invalid/replayed submissions count; peer/context isolation and success retention");

for (const error of [new NonceStoreUnavailable("offline"), new Error("custom backend failure")]) {
    const offlineHistory = new FailedAttemptHistory();
    const offline = harness({
        failureHistory: offlineHistory,
        nonceStore: { async consume() { throw error; } },
    });
    const headers = await solvedHeaders(await offline.request());
    if (error instanceof NonceStoreUnavailable) {
        assert.equal((await offline.request({ headers })).error, "offline");
        assert.equal(offline.seen.at(-1).failed_attempts, 0);
    } else await assert.rejects(offline.request({ headers }), /custom backend failure/);
    assert.equal(offlineHistory.entries.size, 0);
}
const appHistory = new FailedAttemptHistory();
const application = harness({ failureHistory: appHistory });
const appHeaders = await solvedHeaders(await application.request());
application.appError = new Error("application failure");
await assert.rejects(application.request({ headers: appHeaders }), /application failure/);
assert.equal(appHistory.entries.size, 0);
console.log("[ok] nonce backend and downstream application failures do not affect caller history");

let now = 100;
const bounded = new FailedAttemptHistory({ ttlSeconds: 5, maxEntries: 1, maxFailures: 2, clock: () => now });
assert.deepEqual(bounded.recordFailure("route", "peer"), { failed_attempts: 1, history_saturated: true });
now = 104;
assert.deepEqual(bounded.recordFailure("route", "peer"), { failed_attempts: 2, history_saturated: true });
assert.equal(bounded.recordFailure("route", "peer").failed_attempts, 2);
assert.deepEqual(bounded.recordFailure("other", "unknown"), { failed_attempts: 0, history_saturated: true });
assert.equal(bounded.entries.size, 1);
assert.equal([...bounded.entries.keys()][0].length, 64);
now = 90;
assert.equal(bounded.snapshot("route", "peer").failed_attempts, 2);
now = 105;
assert.deepEqual(bounded.snapshot("route", "peer"), { failed_attempts: 0, history_saturated: false });
assert.equal(bounded.entries.size, 0);
assert.equal(bounded.recordFailure("other", "unknown").failed_attempts, 1);
for (const limits of [{ ttlSeconds: 0 }, { maxEntries: -1 }, { maxFailures: 1.5 }, { maxEntries: true }]) {
    assert.throws(() => new FailedAttemptHistory(limits));
}
console.log("[ok] fixed TTL, bounded capacity/count, conservative saturation, rollback and recovery");

for (const context of ["", null, 12]) {
    await assert.rejects(harness({ contextFactory: () => context }).request(), /nonempty string/);
}
const factoryFailure = new Error("context factory failed");
const factoryHistory = new FailedAttemptHistory();
const failedFactory = maxwellsDefense({
    serverSecret: secret,
    failureHistory: factoryHistory,
    contextFactory() { throw factoryFailure; },
});
let forwardedFactoryErrors = 0;
const handledFactoryRequest = failedFactory({ originalUrl: "/api", headers: {} }, {}, (error) => {
    forwardedFactoryErrors += 1;
    assert.equal(error, factoryFailure);
});
assert.equal(handledFactoryRequest instanceof Promise, true);
await handledFactoryRequest;
assert.equal(forwardedFactoryErrors, 1);
assert.equal(factoryHistory.entries.size, 0);
console.log("[ok] context factory errors reach next(error) exactly once without changing caller history");
const example = new FailedAttemptDifficultyOracle({ baseDifficulty: 2, maxDifficulty: 4, failuresPerStep: 2 });
assert.deepEqual(Array.from({ length: 7 }, (_, count) => example.difficulty({}, { failed_attempts: count })), [2, 2, 3, 3, 4, 4, 4]);
assert.equal(example.difficulty({}, { failed_attempts: 0, history_saturated: true }), 4);
assert.throws(() => example.difficulty({}, { failed_attempts: -1 }));
for (const options of [{ maxDifficulty: 33 }, { baseDifficulty: true }, { failuresPerStep: 0 }]) {
    assert.throws(() => new FailedAttemptDifficultyOracle(options));
}
const adaptiveRule = new FailedAttemptDifficultyOracle({ baseDifficulty: 0, maxDifficulty: 2, failuresPerStep: 1 });
const adaptive = harness({ difficultyOracle: (req, signals) => adaptiveRule.difficulty(req, signals) });
assert.equal((await adaptive.request()).challenge.difficulty, 0);
for (const expected of [1, 2, 2]) {
    assert.equal((await adaptive.request({ headers: { "x-maxwell-solution": "{}" } })).challenge.difficulty, expected);
}
const legacy = harness({ difficultyOracle: (req) => req.method === "POST" ? 1 : 0 });
assert.equal((await legacy.request()).challenge.difficulty, 1);
const saturated = harness({
    failureHistory: new FailedAttemptHistory({ maxEntries: 1 }),
    difficultyOracle: (req, signals) => adaptiveRule.difficulty(req, signals),
});
await saturated.request({ headers: { "x-maxwell-solution": "{}" } });
assert.equal((await saturated.request({ peer: "192.0.2.2" })).challenge.difficulty, 2);
console.log("[ok] invalid factory rejection, example escalation/cap and one-argument callback compatibility");
