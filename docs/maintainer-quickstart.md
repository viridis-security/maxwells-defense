<!-- SPDX-License-Identifier: Apache-2.0 -->

# Protect an agent's HTTP entry point

Maxwell puts a computational admission gate before an operation you control. A caller receives a challenge, computes a SHA-256 solution, and resubmits it. The middleware checks the signature, context, expiry and work, then consumes the nonce before forwarding the request. Each admitted request needs fresh work. This gives the maintainer a tunable cost barrier around HTTP agent invocations, HTTP MCP requests, inference triggers or other application endpoints.

```text
Caller -> upstream rate limits -> Maxwell -> authentication/permissions -> application
```

The protected origin must be reachable only through this path. An unprotected alternate route or direct origin connection removes the gate's effect. Keep normal authentication, tool permissions, input validation and resource limits. The reference does not identify malicious callers, filter prompt injection, protect stdio MCP transports, or absorb a packet/bandwidth flood. The ASGI integration forwards non-HTTP scopes without gating them; WebSockets need a separate admission design.

## Run a real local demonstration

From this source checkout, with Node 18 or newer:

```bash
node examples/local-admission/client.mjs
```

The command creates an ephemeral `127.0.0.1` HTTP server using the actual `maxwellsDefense` middleware, solves its challenge using `solveChallenge`, checks the first acceptance, retries the same proof and checks its refusal, then closes the server. No package install, agent account, payment or external destination is needed. It prints JSON containing `challenge_status: 401`, `accepted_status: 200`, `replay_status: 401`, `replay_error: "maxwell_replayed_solution"` and `application_calls: 1`.

The receipt also reports `client_solve_ms` and `server_admission_ms`. Admission timing covers middleware parsing, signature/work checks and nonce consumption, excluding transport and the downstream handler. These are observations from one run on your device; they are not a benchmark comparison or an estimate of electricity use. The demonstration fixes TTL at 60 seconds and defaults to difficulty 12, with an allowed range of 1–16 for programmatic use. Its application handler returns a harmless JSON receipt. It never calls a real agent or executes submitted input. See the [server](../examples/local-admission/server.mjs), [client](../examples/local-admission/client.mjs) and [concurrent admission regression](../javascript/tests/local-admission.test.mjs).

## Install the reviewed reference source

The source declares version 0.2.0; release preparation did not tag or publish it. The previously published 0.1.0 does not include the default single-use middleware change. Until the new version is published, install the reviewed source explicitly:

```bash
git clone https://github.com/viridis-security/maxwells-defense.git
cd maxwells-defense
git checkout 630f9ddeec755b73ae6f360965dc6a9627be8cba
python -m venv .venv
. .venv/bin/activate
python -m pip install -e "./python[fastapi]"
```

This pin contains the runtime integrations below; the new local demonstration is in the checkout containing this guide. JavaScript clients and servers can import its `javascript/src/` modules directly. After a release is published, use an exact package version and a dependency lock file as described in the [pinning guide](integration.md#10-version-pinning-and-typing). Confirm publication before using a package-install command.

## Choose and wrap the expensive operation

Use an entry point that callers must pass before the expensive work starts. The following FastAPI example gates `/agent/` while leaving other paths available. In your existing application, retain its authentication and permissions, then call your authorized agent handler after admission.

```python
import os

from fastapi import FastAPI
from maxwells_defense import StaticDifficultyOracle
from maxwells_defense.middleware import FastAPIMaxwellMiddleware

app = FastAPI()
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=bytes.fromhex(os.environ["MAXWELL_SECRET_HEX"]),
    difficulty_oracle=StaticDifficultyOracle(18),
    protect_path_prefix="/agent/",
    ttl_seconds=60,
)
```

Generate a high-entropy secret of at least 32 bytes and load it from your environment or secret manager; do not commit it. Install FastAPI separately in your application's environment. Generic WSGI applications can use the same options with `WSGIMaxwellMiddleware(existing_wsgi_app, ...)`. For Express, mount the existing middleware before the protected handler:

```js
import { maxwellsDefense } from "./javascript/src/maxwell-express.mjs";

app.use("/agent", maxwellsDefense({
    serverSecret: Buffer.from(process.env.MAXWELL_SECRET_HEX, "hex"),
    difficulty: 18,
    ttlSeconds: 60,
}));
// Register the application's authenticated /agent handlers after the gate.
```

The import is relative to the repository root; adjust it to the reviewed source location in your application. These snippets use a process-local store. Read the shared-state requirements below before running multiple workers or hosts.

## Connect legitimate callers and select a policy

Use the existing browser/Node client wrapper so the caller handles a recognized Maxwell challenge and retries once:

```js
import { fetchWithMaxwell } from "./javascript/src/maxwell.mjs";

const response = await fetchWithMaxwell("https://your-owned-origin.example/agent/invoke", {
    method: "POST",
    headers: { Authorization: yourExistingCredential },
});
```

Use a request body that can be sent again, such as a string, rather than a consumed stream. Cross-origin browser use needs your application's CORS policy to allow the proof headers and expose `X-Maxwell-Provider`. Preserve client cancellation, credentials and application retry/idempotency policy in your integration. Consumption happens before the application finishes: an application failure does not make the proof reusable. See [client integration](integration.md#6-client-integration).

Difficulty defaults to a static 18. At difficulty `d`, a classical fresh search has expected `2^d` candidate hashes under the [random-oracle model](../THEOREMS.md#cryptographic-guarantees). One additional bit doubles expected search work; it does not fix wall time or deployment cost. All admitted callers perform work, including legitimate ones. Measure completion latency on their actual devices before raising difficulty.

Optional `FailedAttemptDifficultyOracle` uses the provided failed-solution count and saturation signal. Successful requests and initial requests without proof do not increment that count. It is a bounded per-process example, not traffic classification or a distributed rate limiter. Route budgets, load feedback and trusted caller identities require a maintainer-supplied oracle/context policy. Peer addresses are transport addresses, and identity headers require your own trusted proxy/authentication configuration. See [context and adaptive signals](integration.md#4-context-binding-and-local-signals).

## Keep single-use state and upstream controls

FastAPI, WSGI and Express create in-memory nonce stores by default. Every verifier sharing a signing secret must share its consumption state. Use a shared Redis store for multiple workers or hosts, configure no eviction and appropriate durability, and rotate the signing secret if acceptance state is lost. Low-level `verify_solution(..., nonce_store=None)` and `verifySolution` without `nonceStore` retain stateless behavior and allow replay within TTL. See [shared-state setup](integration.md#single-use--multi-process-state).

The default in-memory cap is 100,000 accepted nonces; required entries are approximately peak accepted requests per second multiplied by TTL seconds, with burst headroom. It rejects new acceptances when full to preserve single use. Upstream rate/IP limits, an appropriate shorter TTL, and monitoring of store occupancy/rejection reasons help prevent capacity lockout. Redis also has finite capacity. See [store capacity and fail-closed behavior](integration.md#store-capacity-and-fail-closed-behavior).

Measure admitted traffic, legitimate-client success/latency, challenge and rejection rates, store failures, and downstream resource use. Raising the marginal compute cost of admitted abuse is the goal; attacker hardware, parallelism and the value of one successful request determine its economics. Neither this example nor the reference establishes an energy, electricity-savings or guaranteed profitability bound. The [theorem statement](../THEOREMS.md#t-ib-09) separates the computational guarantee from the external thermodynamic assumption.
