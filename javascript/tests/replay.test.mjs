// MX-INV-6: single-use state and Express forwarding contract.
// License: Apache-2.0.

import assert from "node:assert/strict";
import {
    InMemoryNonceStore,
    NonceStoreUnavailable,
    RedisNonceStore,
    ReplayedSolution,
    issueChallenge,
    maxwellsDefense,
    verifySolution,
} from "../src/maxwell-express.mjs";
import { fetchWithMaxwell, solveChallenge } from "../src/maxwell.mjs";

const secret = Buffer.alloc(32, "a");
let now = 1000;
const clock = () => now;
const createChallenge = (contextId = "host/api", ttlSeconds = 10) => issueChallenge({
    serverSecret: secret, contextId, difficulty: 0, ttlSeconds, nowSeconds: now,
});

class FakeRedis {
    constructor() {
        this.keys = new Map();
    }

    async eval(script, { keys, arguments: args }) {
        assert.equal(keys.length, 1);
        assert.match(script, /redis.call\('TIME'\)/);
        assert.match(script, /'SET', KEYS\[1\], '1', 'NX', 'EXAT', expires_at/);
        const [key] = keys;
        const expiresAt = Number(args[0]);
        if (expiresAt <= now) return -1;
        if ((this.keys.get(key) || 0) > now) return 0;
        this.keys.set(key, expiresAt);
        return 1;
    }
}

for (const store of [
    new InMemoryNonceStore({ clock }), new RedisNonceStore(new FakeRedis()),
]) {
    const challenge = createChallenge();
    const solution = await solveChallenge(challenge);
    const verify = () => verifySolution({
        serverSecret: secret, challenge, solution, nonceStore: store, nowSeconds: now,
    });
    await verify();
    await assert.rejects(async () => verify(), ReplayedSolution);
    for (const context of ["host/a", "host/b"]) {
        const distinct = createChallenge(context);
        await verifySolution({
            serverSecret: secret, challenge: distinct,
            solution: await solveChallenge(distinct), expectedContextId: context,
            nonceStore: store, nowSeconds: now,
        });
    }
}
console.log("[ok] in-memory and Redis parity: one acceptance, independent contexts");

const wheel = new InMemoryNonceStore({ maxTtlSeconds: 10, clock });
assert.equal(wheel.consume(Buffer.from("long"), 1010), true);
assert.equal(wheel.consume(Buffer.from("short"), 1002), true);
assert.equal(wheel.consume(Buffer.from("middle"), 1007), true);
now = 1002;
wheel.gc(now);
assert.equal(wheel.entries.size, 2);
now = 1007;
wheel.gc(now);
assert.equal(wheel.entries.size, 1);
assert.equal(wheel.consume(Buffer.from("long"), 1010), false);
now = 1010;
wheel.gc(now);
assert.equal(wheel.entries.size, 0);
assert.throws(() => wheel.consume(Buffer.from("long"), now), /ExpiredChallenge/);
now = 1000;
assert.throws(() => wheel.consume(Buffer.from("long"), 1010), /ExpiredChallenge/);
console.log("[ok] lazy GC handles out-of-order expiry, wrap and clock rollback");

const guarded = new InMemoryNonceStore({ clock });
const guardedChallenge = createChallenge();
const guardedSolution = await solveChallenge(guardedChallenge);
assert.throws(() => verifySolution({
    serverSecret: secret, challenge: guardedChallenge, solution: guardedSolution,
    expectedContextId: "other", nonceStore: guarded, nowSeconds: now,
}), /context mismatch/);
assert.equal(guarded.entries.size, 0);
verifySolution({
    serverSecret: secret, challenge: guardedChallenge, solution: guardedSolution,
    expectedContextId: "host/api", nonceStore: guarded, nowSeconds: now,
});
console.log("[ok] invalid context does not consume valid work");

const capped = new InMemoryNonceStore({ maxEntries: 1, maxTtlSeconds: 10, clock });
assert.equal(capped.consume(Buffer.from("first"), now + 10), true);
assert.throws(
    () => capped.consume(Buffer.from("second"), now + 10), NonceStoreUnavailable,
);
assert.equal(capped.consume(Buffer.from("first"), now + 10), false);
assert.throws(
    () => capped.consume(Buffer.from("too-long"), now + 11), NonceStoreUnavailable,
);
now += 10;
assert.equal(capped.consume(Buffer.from("second"), now + 10), true);
console.log("[ok] capacity never evicts live state; expiry recovers capacity");

const sharedClient = new FakeRedis();
const firstStore = new RedisNonceStore(sharedClient);
const secondStore = new RedisNonceStore(sharedClient);
const outcomes = await Promise.all(Array.from({ length: 16 }, (_, i) =>
    (i % 2 ? firstStore : secondStore).consume(Buffer.from("shared"), now + 10),
));
assert.equal(outcomes.filter(Boolean).length, 1);
await assert.rejects(
    new RedisNonceStore({ eval: async () => { throw new Error("offline"); } })
        .consume(Buffer.from("nonce"), now + 10), NonceStoreUnavailable,
);
await assert.rejects(
    new RedisNonceStore({ eval: async () => null })
        .consume(Buffer.from("nonce"), now + 10), NonceStoreUnavailable,
);
await assert.rejects(
    secondStore.consume(Buffer.from("already-expired"), now), /ExpiredChallenge/,
);
console.log("[ok] shared Redis state has one winner and fails closed on errors or expiry");

const boundary = createChallenge();
const boundarySolution = await solveChallenge(boundary);
verifySolution({
    serverSecret: secret, challenge: boundary, solution: boundarySolution,
    nowSeconds: boundary.expires_at,
});
verifySolution({
    serverSecret: secret, challenge: boundary, solution: boundarySolution,
    nowSeconds: boundary.expires_at,
});
assert.throws(() => verifySolution({
    serverSecret: secret, challenge: boundary, solution: boundarySolution,
    nonceStore: new InMemoryNonceStore({ clock }), nowSeconds: boundary.expires_at,
}), /ExpiredChallenge/);
console.log("[ok] stateless behavior unchanged; single-use expiry is exclusive");

async function exerciseMiddleware(nonceStore) {
    const middleware = maxwellsDefense({
        serverSecret: secret, difficulty: 0, ...(nonceStore ? { nonceStore } : {}),
    });
    const challenge = issueChallenge({ serverSecret: secret, contextId: "host/api", difficulty: 0 });
    const solution = await solveChallenge(challenge);
    const req = {
        originalUrl: "/api",
        headers: {
            host: "host",
            "x-maxwell-challenge": JSON.stringify(challenge),
            "x-maxwell-solution": JSON.stringify(solution),
        },
    };
    const res = {
        code: null, body: null,
        set() { return this; },
        status(code) { this.code = code; return this; },
        json(body) { this.body = body; return this; },
    };
    let forwarded = 0;
    await middleware(req, res, () => { forwarded += 1; });
    assert.equal(forwarded, 1);
    await middleware(req, res, () => { forwarded += 1; });
    assert.equal(forwarded, 1);
    assert.equal(res.code, 401);
    assert.equal(res.body.error, "maxwell_replayed_solution");
    assert.notEqual(res.body.challenge.server_nonce, challenge.server_nonce);
}

await exerciseMiddleware();
now = Math.floor(Date.now() / 1000);
await exerciseMiddleware(new RedisNonceStore(new FakeRedis()));
assert.throws(() => maxwellsDefense({ serverSecret: secret, nonceStore: null }));
console.log("[ok] Express defaults and asynchronous shared store reject replay before forwarding");

const oracleFailure = new Error("oracle failed");
let forwardedError;
let errorCalls = 0;
const failedOracle = maxwellsDefense({
    serverSecret: secret,
    difficultyOracle() { throw oracleFailure; },
});
await failedOracle({ originalUrl: "/api", headers: { host: "host" } }, {}, (error) => {
    errorCalls += 1;
    forwardedError = error;
});
assert.equal(errorCalls, 1);
assert.equal(forwardedError, oracleFailure);

for (const asynchronous of [false, true]) {
    const storeFailure = new TypeError("custom store failed");
    const failedStore = maxwellsDefense({
        serverSecret: secret,
        difficulty: 0,
        nonceStore: {
            consume() {
                if (asynchronous) return Promise.reject(storeFailure);
                throw storeFailure;
            },
        },
    });
    const challenge = issueChallenge({ serverSecret: secret, contextId: "host/api", difficulty: 0 });
    errorCalls = 0;
    await failedStore({
        originalUrl: "/api",
        headers: {
            host: "host",
            "x-maxwell-challenge": JSON.stringify(challenge),
            "x-maxwell-solution": JSON.stringify(await solveChallenge(challenge)),
        },
    }, {}, (error) => {
        errorCalls += 1;
        forwardedError = error;
    });
    assert.equal(errorCalls, 1);
    assert.equal(forwardedError, storeFailure);
}
console.log("[ok] Express forwards oracle and synchronous/asynchronous store failures to next(error)");

const originalFetch = globalThis.fetch;
try {
    const challenge = issueChallenge({
        serverSecret: secret, contextId: "host/東京/🛡️", difficulty: 0,
    });
    let calls = 0;
    globalThis.fetch = async (input, init = {}) => {
        calls += 1;
        assert.equal(input, "https://fixture.invalid/api");
        if (calls === 1) {
            return new Response(JSON.stringify({ challenge }), {
                status: 401,
                headers: { "X-Maxwell-Provider": "viridis-security.com" },
            });
        }
        const header = init.headers.get("X-Maxwell-Challenge");
        assert.match(header, /^[\x20-\x7e]+$/);
        const echoed = JSON.parse(header);
        assert.deepEqual(echoed, challenge);
        verifySolution({
            serverSecret: secret,
            challenge: echoed,
            solution: JSON.parse(init.headers.get("X-Maxwell-Solution")),
            expectedContextId: challenge.context_id,
            nonceStore: new InMemoryNonceStore(),
        });
        return new Response("ok", { status: 200 });
    };
    const response = await fetchWithMaxwell("https://fixture.invalid/api");
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok");
    assert.equal(calls, 2);
} finally {
    globalThis.fetch = originalFetch;
}
console.log("[ok] fetch wrapper completes a Unicode-context challenge roundtrip with ASCII headers");
