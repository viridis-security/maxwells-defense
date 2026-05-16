// Maxwell's Defense — client-side challenge solver (JavaScript / Web).
//
// Mirrors the Python reference at python/maxwells_defense/core.py. Agents
// and browsers solve challenges by extending the server-issued nonce until
// SHA-256(server_nonce || solution_nonce) has the required leading zero
// bits.
//
// Defense primitive only — no exploit code. Apache-2.0.
//
// Usage in a browser or Node 18+ environment:
//
//     import { solveChallenge, fetchWithMaxwell } from "./maxwell.mjs";
//
//     // Wrap fetch() — automatically solves if a 401 returns a challenge.
//     const res = await fetchWithMaxwell("/api/protected", { method: "GET" });
//
// Usage in an AI agent harness (raw API):
//
//     const challenge = await getChallenge();  // your transport
//     const solution = await solveChallenge(challenge);
//     await callWithSolution(challenge, solution);

const PROVIDER_HEADER = "x-maxwell-provider";
const CHALLENGE_HEADER = "X-Maxwell-Challenge";
const SOLUTION_HEADER = "X-Maxwell-Solution";

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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

async function sha256(...parts) {
    const total = parts.reduce((acc, p) => acc + p.length, 0);
    const buf = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        buf.set(p, offset);
        offset += p.length;
    }
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return new Uint8Array(digest);
}

function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
}

/**
 * Solve a Maxwell's Defense challenge.
 *
 * @param {Object} challenge - { server_nonce (hex), difficulty (int), ...
 *                               other fields are passed through opaquely }
 * @param {Object} [opts]
 * @param {number} [opts.maxIterations] hard cap; default 4 * 2^difficulty
 * @returns {Promise<{solution_nonce: string}>}
 */
export async function solveChallenge(challenge, opts = {}) {
    const difficulty = challenge.difficulty | 0;
    const serverNonce = hexToBytes(challenge.server_nonce);
    const maxIterations =
        opts.maxIterations ?? Math.max(1024, 4 * (1 << difficulty));

    for (let i = 0; i < maxIterations; i++) {
        const cand = randomBytes(16);
        const digest = await sha256(serverNonce, cand);
        if (leadingZeroBits(digest) >= difficulty) {
            return { solution_nonce: bytesToHex(cand) };
        }
    }
    throw new Error(
        `solveChallenge: exhausted ${maxIterations} iterations at difficulty=${difficulty}`,
    );
}

/**
 * Drop-in fetch wrapper. If the server returns 401 with a Maxwell
 * challenge, solves it and retries once.
 *
 * @param {string|Request} input
 * @param {RequestInit} [init]
 * @returns {Promise<Response>}
 */
export async function fetchWithMaxwell(input, init = {}) {
    const res = await fetch(input, init);
    if (res.status !== 401) return res;
    if (!res.headers.get(PROVIDER_HEADER)) return res;

    let body;
    try {
        body = await res.clone().json();
    } catch {
        return res; // not a Maxwell challenge after all
    }
    if (!body?.challenge) return res;

    const solution = await solveChallenge(body.challenge);
    const headers = new Headers(init.headers || {});
    headers.set(CHALLENGE_HEADER, JSON.stringify(body.challenge));
    headers.set(SOLUTION_HEADER, JSON.stringify(solution));
    return fetch(input, { ...init, headers });
}

export const _internal = { leadingZeroBits, hexToBytes, bytesToHex };
