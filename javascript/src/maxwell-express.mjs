// Express middleware for Maxwell's Defense (Node 18+).
//
// Mirrors the Python FastAPIMaxwellMiddleware. Server-side only: issues
// HMAC-bound challenges, verifies solutions in O(1), forwards to the
// downstream handler on success.
//
// Apache-2.0.

import { createHmac, randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

const PROVIDER_HEADER = "X-Maxwell-Provider";
const PROVIDER_VALUE = "viridis-security.com";
const CHALLENGE_HEADER = "x-maxwell-challenge";
const SOLUTION_HEADER = "x-maxwell-solution";

let shortSecretWarningIssued = false;

function warnIfShortSecret(serverSecret) {
    if (serverSecret.length < 32 && !shortSecretWarningIssued) {
        shortSecretWarningIssued = true;
        process.emitWarning("serverSecret is shorter than 32 bytes; use a high-entropy key of at least 32 bytes in production", {
            type: "MaxwellSecurityWarning",
            code: "MAXWELL_SHORT_SECRET",
        });
    }
}

export class ReplayedSolution extends Error {
    constructor() {
        super("maxwell_replayed_solution");
        this.name = "ReplayedSolution";
    }
}

export class NonceStoreUnavailable extends Error {
    constructor(message = "nonce store is unavailable") {
        super(message);
        this.name = "NonceStoreUnavailable";
    }
}

/** Bounded per-process fixed-window signals, separate from nonce acceptance. */
export class FailedAttemptHistory {
    constructor({
        ttlSeconds = 300, maxEntries = 10_000, maxFailures = 1_000_000,
        clock = () => performance.now() / 1000,
    } = {}) {
        for (const limit of [ttlSeconds, maxEntries, maxFailures]) {
            if (!Number.isSafeInteger(limit) || limit < 1) {
                throw new Error("history limits must be positive safe integers");
            }
        }
        this.ttlSeconds = ttlSeconds;
        this.maxEntries = maxEntries;
        this.maxFailures = maxFailures;
        this.clock = clock;
        this.lastNow = clock();
        this.entries = new Map();
    }

    key(contextId, remoteAddr) {
        return createHash("sha256").update(JSON.stringify([contextId, remoteAddr])).digest("hex");
    }

    gc() {
        const now = Math.max(this.clock(), this.lastNow);
        for (const [key, entry] of this.entries) {
            if (entry.expiresAt > now) break;
            this.entries.delete(key);
        }
        this.lastNow = now;
        return now;
    }

    snapshot(contextId, remoteAddr) {
        this.gc();
        const count = this.entries.get(this.key(contextId, remoteAddr))?.count || 0;
        return {
            failed_attempts: count,
            history_saturated: this.entries.size >= this.maxEntries || count >= this.maxFailures,
        };
    }

    recordFailure(contextId, remoteAddr) {
        const now = this.gc();
        const key = this.key(contextId, remoteAddr);
        const entry = this.entries.get(key);
        if (entry) entry.count = Math.min(entry.count + 1, this.maxFailures);
        else if (this.entries.size < this.maxEntries) {
            this.entries.set(key, { count: 1, expiresAt: now + this.ttlSeconds });
        }
        return this.snapshot(contextId, remoteAddr);
    }
}

/** Example capped local rule; opt in via (req, signals) => oracle.difficulty(req, signals). */
export class FailedAttemptDifficultyOracle {
    constructor({ baseDifficulty = 12, maxDifficulty = 20, failuresPerStep = 3 } = {}) {
        if (!Number.isInteger(baseDifficulty) || !Number.isInteger(maxDifficulty) ||
            baseDifficulty < 0 || baseDifficulty > maxDifficulty || maxDifficulty > 32) {
            throw new Error("difficulty bounds must be integers in [0, 32]");
        }
        if (!Number.isSafeInteger(failuresPerStep) || failuresPerStep < 1) {
            throw new Error("failuresPerStep must be a positive safe integer");
        }
        this.baseDifficulty = baseDifficulty;
        this.maxDifficulty = maxDifficulty;
        this.failuresPerStep = failuresPerStep;
    }

    difficulty(req, signals) {
        const failures = signals.failed_attempts ?? 0;
        if (!Number.isSafeInteger(failures) || failures < 0) {
            throw new Error("failed_attempts must be a nonnegative safe integer");
        }
        if (signals.history_saturated) return this.maxDifficulty;
        return Math.min(this.maxDifficulty,
            this.baseDifficulty + Math.floor(failures / this.failuresPerStep));
    }
}

/** Single-process atomic state, with bounded lazy expiry and no live eviction. */
export class InMemoryNonceStore {
    constructor({
        maxEntries = 100_000,
        maxTtlSeconds = 300,
        clock = () => Math.floor(Date.now() / 1000),
    } = {}) {
        if (!Number.isInteger(maxEntries) || maxEntries < 1 ||
            !Number.isInteger(maxTtlSeconds) || maxTtlSeconds < 1) {
            throw new Error("maxEntries and maxTtlSeconds must be positive integers");
        }
        this.maxEntries = maxEntries;
        this.maxTtlSeconds = maxTtlSeconds;
        this.slots = maxTtlSeconds + 1;
        this.clock = clock;
        this.lastGc = clock();
        this.entries = new Map();
        this.buckets = new Map();
        this.occupied = 0n;
    }

    consume(nonce, expiresAt) {
        const now = Math.max(this.clock(), this.lastGc);
        this.gc(now);
        if (expiresAt <= now) throw new Error("ExpiredChallenge");
        if (expiresAt - now > this.maxTtlSeconds) {
            throw new NonceStoreUnavailable("expiry exceeds the store retention horizon");
        }
        const key = nonce.toString("hex");
        if (this.entries.has(key)) return false;
        if (this.entries.size >= this.maxEntries) {
            throw new NonceStoreUnavailable("nonce store capacity reached");
        }
        const slot = expiresAt % this.slots;
        this.entries.set(key, expiresAt);
        if (!this.buckets.has(slot)) this.buckets.set(slot, new Set());
        this.buckets.get(slot).add(key);
        this.occupied |= 1n << BigInt(slot);
        return true;
    }

    gc(now) {
        const elapsed = now - this.lastGc;
        if (elapsed <= 0) return;
        if (elapsed >= this.slots) {
            this.entries.clear();
            this.buckets.clear();
            this.occupied = 0n;
        } else {
            const start = (this.lastGc + 1) % this.slots;
            let mask = ((1n << BigInt(elapsed)) - 1n) << BigInt(start);
            mask = (mask & ((1n << BigInt(this.slots)) - 1n)) |
                (mask >> BigInt(this.slots));
            let expired = this.occupied & mask;
            this.occupied &= ~expired;
            while (expired) {
                const bit = expired & -expired;
                const slot = bit.toString(2).length - 1;
                for (const key of this.buckets.get(slot)) this.entries.delete(key);
                this.buckets.delete(slot);
                expired ^= bit;
            }
        }
        this.lastGc = now;
    }
}

const CONSUME_SCRIPT = `
local expires_at = tonumber(ARGV[1])
local now = tonumber(redis.call('TIME')[1])
if expires_at <= now then return -1 end
local accepted = redis.call('SET', KEYS[1], '1', 'NX', 'EXAT', expires_at)
if accepted then return 1 end
return 0
`;

/** Optional shared state: inject a connected node-redis-compatible client. */
export class RedisNonceStore {
    constructor(client, { keyPrefix = "maxwell:nonce:" } = {}) {
        this.client = client;
        this.keyPrefix = keyPrefix;
    }

    async consume(nonce, expiresAt) {
        let result;
        try {
            result = await this.client.eval(CONSUME_SCRIPT, {
                keys: [this.keyPrefix + nonce.toString("hex")],
                arguments: [String(expiresAt)],
            });
        } catch (error) {
            throw new NonceStoreUnavailable("Redis nonce state is unavailable");
        }
        if (result === -1) throw new Error("ExpiredChallenge");
        if (result !== 0 && result !== 1) {
            throw new NonceStoreUnavailable("unexpected Redis consume result");
        }
        return result === 1;
    }

    gc(now) {
        // Redis evicts at EXAT using its own clock.
    }
}

function hmacPayload(serverNonce, difficulty, expiresAt, contextId) {
    const sep = Buffer.from("|");
    return Buffer.concat([
        Buffer.from(serverNonce, "hex"),
        sep,
        Buffer.from(String(difficulty)),
        sep,
        Buffer.from(String(expiresAt)),
        sep,
        Buffer.from(contextId, "utf8"),
    ]);
}

function leadingZeroBits(bytes) {
    let n = 0;
    for (const b of bytes) {
        if (b === 0) {
            n += 8;
            continue;
        }
        for (let i = 7; i >= 0; i--) {
            if ((b >> i) & 1) return n;
            n += 1;
        }
        return n;
    }
    return n;
}

export function issueChallenge({
    serverSecret,
    contextId,
    difficulty,
    ttlSeconds = 300,
    nowSeconds = Math.floor(Date.now() / 1000),
}) {
    if (!Buffer.isBuffer(serverSecret) || serverSecret.length === 0) {
        throw new Error("serverSecret must be a non-empty Buffer");
    }
    warnIfShortSecret(serverSecret);
    if (!(difficulty >= 0 && difficulty <= 32)) {
        throw new Error("difficulty must be in [0, 32]");
    }
    if (!(ttlSeconds > 0)) {
        throw new Error("ttlSeconds must be positive");
    }
    const serverNonce = randomBytes(16);
    const expiresAt = nowSeconds + ttlSeconds;
    const sig = createHmac("sha256", serverSecret)
        .update(
            hmacPayload(
                serverNonce.toString("hex"),
                difficulty,
                expiresAt,
                contextId,
            ),
        )
        .digest();
    return {
        server_nonce: serverNonce.toString("hex"),
        difficulty,
        expires_at: expiresAt,
        context_id: contextId,
        hmac_sig: sig.toString("hex"),
    };
}

export function verifySolution({
    serverSecret,
    challenge,
    solution,
    expectedContextId,
    nonceStore,
    nowSeconds = Math.floor(Date.now() / 1000),
}) {
    const sig = createHmac("sha256", serverSecret)
        .update(
            hmacPayload(
                challenge.server_nonce,
                challenge.difficulty,
                challenge.expires_at,
                challenge.context_id,
            ),
        )
        .digest();
    const provided = Buffer.from(challenge.hmac_sig, "hex");
    if (sig.length !== provided.length || !timingSafeEqual(sig, provided)) {
        throw new Error("SignatureMismatch");
    }
    if (expectedContextId && expectedContextId !== challenge.context_id) {
        throw new Error("InvalidSolution: context mismatch");
    }
    if (nowSeconds > challenge.expires_at ||
        (nonceStore && nowSeconds === challenge.expires_at)) {
        throw new Error("ExpiredChallenge");
    }
    const digest = createHash("sha256")
        .update(Buffer.from(challenge.server_nonce, "hex"))
        .update(Buffer.from(solution.solution_nonce, "hex"))
        .digest();
    if (leadingZeroBits(digest) < challenge.difficulty) {
        throw new Error("InsufficientWork");
    }
    // Stateless calls remain synchronous and retain their historical behavior.
    // Shared stores may return a Promise; callers must await verification.
    if (nonceStore) {
        const consumed = nonceStore.consume(
            Buffer.from(challenge.server_nonce, "hex"), challenge.expires_at,
        );
        const checkConsumed = (accepted) => {
            if (!accepted) throw new ReplayedSolution();
        };
        if (consumed && typeof consumed.then === "function") {
            return consumed.then(checkConsumed);
        }
        checkConsumed(consumed);
    }
}

/**
 * Express middleware factory.
 *
 * Usage:
 *
 *     import express from "express";
 *     import { maxwellsDefense } from "./maxwell-express.mjs";
 *
 *     const app = express();
 *     app.use("/api", maxwellsDefense({
 *         serverSecret: Buffer.from(process.env.MAXWELL_SECRET, "hex"),
 *         difficulty: 18,
 *     }));
 */
export function maxwellsDefense(opts) {
    const {
        serverSecret,
        difficulty = 18,
        ttlSeconds = 300,
        difficultyOracle, // optional (req, signals) => number; one-argument callbacks still work
        contextFactory, // optional (req, signals) => nonempty context string
        failureHistory = new FailedAttemptHistory(),
        nonceStore = new InMemoryNonceStore({ maxTtlSeconds: ttlSeconds }),
        challengeStatusCode = 401,
        retryAfterSeconds = 1,
    } = opts || {};
    if (!Buffer.isBuffer(serverSecret) || serverSecret.length === 0) {
        throw new Error("maxwellsDefense: serverSecret must be a non-empty Buffer");
    }
    warnIfShortSecret(serverSecret);
    if (!nonceStore || typeof nonceStore.consume !== "function") {
        throw new Error("maxwellsDefense: nonceStore must implement consume");
    }
    if (challengeStatusCode !== 401 && challengeStatusCode !== 429) {
        throw new Error("maxwellsDefense: challengeStatusCode must be 401 or 429");
    }
    if (!Number.isInteger(retryAfterSeconds) || retryAfterSeconds < 0) {
        throw new Error("maxwellsDefense: retryAfterSeconds must be a nonnegative integer");
    }
    const handleRequest = async function (req, res, next) {
        const signals = {
            remote_addr: req.socket?.remoteAddress ?? null,
            method: req.method || "GET",
            path: req.originalUrl,
        };
        const contextId = contextFactory
            ? contextFactory(req, Object.freeze({ ...signals }))
            : (req.headers.host || "default") + req.originalUrl;
        if (typeof contextId !== "string" || !contextId) {
            throw new Error("contextFactory must return a nonempty string");
        }
        Object.assign(signals, failureHistory.snapshot(contextId, signals.remote_addr));
        const reject = (error, countFailure) => {
            if (countFailure) {
                Object.assign(signals, failureHistory.recordFailure(contextId, signals.remote_addr));
            }
            return sendChallenge(res, {
                serverSecret, contextId,
                difficulty: difficultyOracle ? difficultyOracle(req, Object.freeze({ ...signals })) : difficulty,
                ttlSeconds, challengeStatusCode, retryAfterSeconds, error,
            });
        };

        const chalHeader = req.headers[CHALLENGE_HEADER];
        const solHeader = req.headers[SOLUTION_HEADER];

        if (chalHeader && solHeader) {
            let challenge, solution;
            try {
                challenge = JSON.parse(chalHeader);
                solution = JSON.parse(solHeader);
                // Malformed input is caller history; backend exceptions are not.
                if (!challenge || !solution ||
                    typeof challenge.server_nonce !== "string" ||
                    typeof challenge.hmac_sig !== "string" ||
                    typeof challenge.context_id !== "string" ||
                    !Number.isInteger(challenge.difficulty) ||
                    !Number.isInteger(challenge.expires_at) ||
                    typeof solution.solution_nonce !== "string") {
                    throw new Error("InvalidSolution: malformed headers");
                }
            } catch (error) {
                return reject("InvalidSolution: malformed headers", true);
            }
            try {
                await verifySolution({
                    serverSecret,
                    challenge,
                    solution,
                    expectedContextId: contextId,
                    nonceStore,
                });
            } catch (e) {
                if (e instanceof NonceStoreUnavailable) return reject(e.message, false);
                if (e instanceof ReplayedSolution || [
                    "SignatureMismatch", "InvalidSolution: context mismatch",
                    "ExpiredChallenge", "InsufficientWork",
                ].includes(e.message)) return reject(e.message, true);
                throw e;
            }
            return next();
        }

        const partial = CHALLENGE_HEADER in req.headers || SOLUTION_HEADER in req.headers;
        return reject(undefined, partial);
    };
    return function (req, res, next) {
        // Express 4 does not forward rejected middleware Promises itself.
        return handleRequest(req, res, next).catch(next);
    };
}

function sendChallenge(res, {
    serverSecret, contextId, difficulty, ttlSeconds, error,
    challengeStatusCode, retryAfterSeconds,
}) {
    const challenge = issueChallenge({
        serverSecret,
        contextId,
        difficulty,
        ttlSeconds,
    });
    res.set(PROVIDER_HEADER, PROVIDER_VALUE);
    // Header values must remain ASCII even when the route contains Unicode.
    const challengeHeader = JSON.stringify(challenge).replace(/[\u007f-\uffff]/g,
        (character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
    res.set("X-Maxwell-Challenge", challengeHeader);
    if (challengeStatusCode === 429) res.set("Retry-After", String(retryAfterSeconds));
    res.status(challengeStatusCode).json({
        error: error || "maxwell_challenge_required",
        challenge,
        spec: "https://github.com/viridis-security/maxwells-defense",
    });
}
