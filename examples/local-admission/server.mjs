// SPDX-License-Identifier: Apache-2.0
// Local HTTP admission example using the actual Express middleware.

import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { maxwellsDefense } from "../../javascript/src/maxwell-express.mjs";

export const DEMO_PATH = "/agent/invoke";

/** This adapter demonstrates admission, not a production agent or proxy. */
export function createDemoServer({ difficulty = 12 } = {}) {
    if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 16) {
        throw new Error("local demo difficulty must be an integer in [1, 16]");
    }
    let applicationCalls = 0;
    const middleware = maxwellsDefense({
        serverSecret: randomBytes(32), // Ephemeral: restarting rotates the secret.
        difficulty,
        ttlSeconds: 60,
    });
    const server = createServer({ maxHeaderSize: 8192 }, (req, res) => {
        const json = (status, body) => {
            res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
            res.end(JSON.stringify(body));
        };
        if (req.url !== DEMO_PATH) return json(404, { error: "not_found" });
        if (req.method !== "POST") return json(405, { error: "post_required" });
        // The demo accepts an empty request only and never executes user input.
        if (req.headers["transfer-encoding"] ||
            (req.headers["content-length"] && req.headers["content-length"] !== "0")) {
            return json(413, { error: "demo_requires_empty_body" });
        }
        for (const name of ["x-maxwell-challenge", "x-maxwell-solution"]) {
            const value = req.headers[name];
            if (value && (typeof value !== "string" || Buffer.byteLength(value) > 2048)) {
                return json(431, { error: "demo_header_too_large" });
            }
        }
        req.originalUrl = req.url;
        const started = performance.now();
        // Only these three Express response methods are needed by the SDK.
        const response = {
            set(name, value) { res.setHeader(name, value); return this; },
            status(code) { res.statusCode = code; return this; },
            json(body) { json(res.statusCode, body); return this; },
        };
        void middleware(req, response, (error) => {
            if (error) return json(500, { error: "demo_admission_failed" });
            const admissionMs = performance.now() - started;
            applicationCalls += 1;
            return json(200, {
                status: "admitted",
                application_calls: applicationCalls,
                server_admission_ms: admissionMs,
            });
        });
    });
    server.requestTimeout = 5000;
    server.headersTimeout = 5000;
    return { server, getApplicationCalls: () => applicationCalls };
}

/** Bind to an ephemeral IPv4 loopback port; no external listener is offered. */
export async function startDemoServer(options = {}) {
    const demo = createDemoServer(options);
    await new Promise((resolve, reject) => {
        demo.server.once("error", reject);
        demo.server.listen(0, "127.0.0.1", resolve);
    });
    return {
        ...demo,
        url: `http://127.0.0.1:${demo.server.address().port}${DEMO_PATH}`,
        close: () => new Promise((resolve, reject) => {
            demo.server.close((error) => error ? reject(error) : resolve());
            demo.server.closeAllConnections?.();
        }),
    };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    const demo = await startDemoServer();
    console.log(`Local protected endpoint: ${demo.url}`);
    console.log("POST an empty request for a challenge. Ctrl+C stops the demo.");
    for (const signal of ["SIGINT", "SIGTERM"]) {
        process.once(signal, () => { void demo.close(); });
    }
}
