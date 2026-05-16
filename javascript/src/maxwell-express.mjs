// Express middleware for Maxwell's Defense (Node 18+).
//
// Mirrors the Python FastAPIMaxwellMiddleware. Server-side only: issues
// HMAC-bound challenges, verifies solutions in O(1), forwards to the
// downstream handler on success.
//
// Apache-2.0.

import { createHmac, randomBytes, timingSafeEqual, createHash } from "node:crypto";

const PROVIDER_HEADER = "X-Maxwell-Provider";
const PROVIDER_VALUE = "viridis-security.com";
const CHALLENGE_HEADER = "x-maxwell-challenge";
const SOLUTION_HEADER = "x-maxwell-solution";

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
    if (nowSeconds > challenge.expires_at) {
        throw new Error("ExpiredChallenge");
    }
    const digest = createHash("sha256")
        .update(Buffer.from(challenge.server_nonce, "hex"))
        .update(Buffer.from(solution.solution_nonce, "hex"))
        .digest();
    if (leadingZeroBits(digest) < challenge.difficulty) {
        throw new Error("InsufficientWork");
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
        difficultyOracle, // optional (req) => number
    } = opts || {};
    if (!Buffer.isBuffer(serverSecret) || serverSecret.length === 0) {
        throw new Error("maxwellsDefense: serverSecret must be a non-empty Buffer");
    }
    return function (req, res, next) {
        const contextId = (req.headers.host || "default") + req.originalUrl;

        const chalHeader = req.headers[CHALLENGE_HEADER];
        const solHeader = req.headers[SOLUTION_HEADER];

        if (chalHeader && solHeader) {
            try {
                const challenge = JSON.parse(chalHeader);
                const solution = JSON.parse(solHeader);
                verifySolution({
                    serverSecret,
                    challenge,
                    solution,
                    expectedContextId: contextId,
                });
                return next();
            } catch (e) {
                return sendChallenge(res, {
                    serverSecret,
                    contextId,
                    difficulty: difficultyOracle
                        ? difficultyOracle(req)
                        : difficulty,
                    ttlSeconds,
                    error: e.message,
                });
            }
        }

        return sendChallenge(res, {
            serverSecret,
            contextId,
            difficulty: difficultyOracle ? difficultyOracle(req) : difficulty,
            ttlSeconds,
        });
    };
}

function sendChallenge(res, { serverSecret, contextId, difficulty, ttlSeconds, error }) {
    const challenge = issueChallenge({
        serverSecret,
        contextId,
        difficulty,
        ttlSeconds,
    });
    res.set(PROVIDER_HEADER, PROVIDER_VALUE);
    res.status(401).json({
        error: error || "maxwell_challenge_required",
        challenge,
        spec: "https://github.com/viridis-security/maxwells-defense",
    });
}
