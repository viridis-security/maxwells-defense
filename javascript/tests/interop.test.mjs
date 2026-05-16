// Cross-language interop test.
//
// 1. Node issues a Maxwell challenge via maxwell-express.mjs::issueChallenge.
// 2. Browser-style solver in maxwell.mjs::solveChallenge solves it.
// 3. Same Node code verifies the solution.
// 4. The challenge JSON is written to a file so the Python suite can
//    re-verify it (proving wire-format compatibility).
//
// We assert in this script. Run from `javascript/`:
//     node tests/interop.test.mjs

import { writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { solveChallenge } from "../src/maxwell.mjs";
import { issueChallenge, verifySolution } from "../src/maxwell-express.mjs";

const secret = randomBytes(32);
const challenge = issueChallenge({
    serverSecret: secret,
    contextId: "test-host:0/api/x",
    difficulty: 12,
    ttlSeconds: 60,
});
console.log("challenge:", JSON.stringify(challenge, null, 2));

const t0 = Date.now();
const solution = await solveChallenge(challenge);
const elapsed = Date.now() - t0;
console.log(`solve took ${elapsed}ms`);
console.log("solution:", solution);

verifySolution({
    serverSecret: secret,
    challenge,
    solution,
    expectedContextId: challenge.context_id,
});
console.log("[ok] JS roundtrip verified");

// Tamper test — flipping difficulty should fail verification.
const tampered = { ...challenge, difficulty: 0 };
try {
    verifySolution({
        serverSecret: secret,
        challenge: tampered,
        solution,
        expectedContextId: challenge.context_id,
    });
    console.error("[FAIL] tampered difficulty was accepted");
    process.exit(1);
} catch (e) {
    if (!String(e.message).includes("SignatureMismatch")) {
        console.error("[FAIL] wrong error type:", e.message);
        process.exit(1);
    }
    console.log("[ok] tampered difficulty rejected (SignatureMismatch)");
}

// Wire-format dump for Python interop verification.
writeFileSync(
    "/tmp/maxwell-interop.json",
    JSON.stringify(
        {
            secret_hex: secret.toString("hex"),
            challenge,
            solution,
            expected_context_id: challenge.context_id,
        },
        null,
        2,
    ),
);
console.log("[ok] wrote /tmp/maxwell-interop.json for Python verifier");
