# Production Integration Guide

Start with the [maintainer quickstart](maintainer-quickstart.md) for a runnable local HTTP admission demo and the path from an agent entry point to a protected integration. This guide covers the deployment details.

Maxwell's Defense ships ~250 LOC of crypto. Wiring it into a production service is mostly about three operational decisions: secret management, difficulty tuning, and where in your request stack the middleware sits. This guide is the checklist.

## 1. Server secret

The HMAC server secret signs challenges; the nonce store retains single-use acceptance state. If you ever change the secret, every outstanding challenge becomes unverifiable (and the verifier raises `SignatureMismatch`) — that's the intended fail-closed behaviour.

**Generation:**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
# or
openssl rand -hex 32
```

**Storage:** treat it like any production HMAC key. Environment variable, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, etc. **Never check it into git.**

Nonempty secrets shorter than 32 bytes remain accepted for compatibility, but Python challenge issuance and middleware setup emit `UserWarning`; Node emits `MAXWELL_SHORT_SECRET` once per loaded module. Warnings contain no key material. Empty secrets still raise an error. Length alone does not establish entropy: generate random keys as shown above.

**Rotation:** the middleware accepts exactly one secret. For seamless rotation, accept two secrets during a transition window — try the current first, fall back to the previous on `SignatureMismatch`, then drop the previous after the TTL of the longest-lived challenge expires.

## 2. Choosing difficulty

Difficulty is leading zero bits in `sha256(server_nonce || solution_nonce)`. Costs scale exponentially.

| Difficulty | Expected solve time on a modern CPU | Use case |
| ---------- | ----------------------------------- | -------- |
| `d = 10`   | < 10 ms                             | Low-friction first touch — token issuance, signup. |
| `d = 16`   | ~200 ms                             | Default for protected APIs. Human-imperceptible, makes batch-scraping painful. |
| `d = 20`   | ~3 s                                | High-value endpoints, suspected attack contexts. |
| `d = 22`   | ~12 s                               | Aggressive rate limiting. Use sparingly — legit clients will complain. |
| `d = 24+`  | Minutes                             | Lockout / triage queue. |

Tune by deploying at `d = 12` for a week, watching attack volume vs. legit-client error rates, then walking it up.

## 3. Where the middleware sits

```
[client] --- TLS terminator --- WAF --- rate limiter --- Maxwell --- your app
```

- **After TLS termination, after the WAF.** You want the challenge body to be unwrapped so callers can read it.
- **Before any expensive auth path** (DB lookups, OAuth introspection). Maxwell's whole point is to spend attacker CPU before yours.
- **After IP-based rate limiting** (if you have one). Rate limiting handles the cheap case; Maxwell handles the case where the attacker is willing to spend per-request.

## 4. Context binding and local signals

The default context is unchanged: Python uses `host + path`; Express uses `host + originalUrl` (including the query string). It does not identify a caller. HMAC binds the context string to the challenge, and the nonce store separately enforces single use.

Both Python middlewares accept `context_factory(default_context, signals)`; Express accepts `contextFactory(req, signals)`. Each callback must return a nonempty string. The factory receives a read-only snapshot of `remote_addr`, `method`, and `path`. For example, bind to the transport peer as well as the default route:

```python
import hashlib
import json
from maxwells_defense import FailedAttemptDifficultyOracle, FailedAttemptHistory
from maxwells_defense.middleware import FastAPIMaxwellMiddleware

def peer_context(default_context, signals):
    return hashlib.sha256(json.dumps([
        default_context, signals["remote_addr"],
    ]).encode()).hexdigest()

app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    context_factory=peer_context,
    failure_history=FailedAttemptHistory(ttl_seconds=300, max_entries=10_000),
    difficulty_oracle=FailedAttemptDifficultyOracle(
        base_difficulty=12, max_difficulty=20, failures_per_step=3,
    ),
)
```

```js
import { createHash } from "node:crypto";
import {
    FailedAttemptDifficultyOracle, FailedAttemptHistory, maxwellsDefense,
} from "@viridis-security/maxwells-defense/express";

const oracle = new FailedAttemptDifficultyOracle({
    baseDifficulty: 12, maxDifficulty: 20, failuresPerStep: 3,
});
app.use(maxwellsDefense({
    serverSecret: SECRET,
    contextFactory: (req, signals) => createHash("sha256")
        .update(JSON.stringify([
            (req.headers.host || "default") + req.originalUrl, signals.remote_addr,
        ])).digest("hex"),
    failureHistory: new FailedAttemptHistory({ ttlSeconds: 300, maxEntries: 10_000 }),
    difficultyOracle: (req, signals) => oracle.difficulty(req, signals),
}));
```

`remote_addr` comes only from ASGI `scope.client`, WSGI `REMOTE_ADDR`, or Node `req.socket.remoteAddress`. It is `None`/`null` when unavailable. Maxwell does not use `Forwarded`, `X-Forwarded-For`, or Express `req.ip`. Behind a proxy this is the proxy's address. A custom factory can include an authenticated identity established by trusted application middleware; claimed agent names and arbitrary proxy headers are not authenticated identities. Configure proxy trust at that boundary explicitly. A changing peer address changes a peer-bound context.

### Adaptive difficulty is opt-in

The default oracle remains static at difficulty 18. On every challenge response, Python calls `oracle(context_id, signals)` and Express calls `difficultyOracle(req, signals)`. Existing one-argument Express callbacks still work. The read-only signal mapping contains:

| Signal | Meaning |
| --- | --- |
| `remote_addr` | Transport peer address, or `None`/`null`. |
| `method` | Request method (default `GET` if absent). |
| `path` | Python path or Express original URL. |
| `failed_attempts` | Retained failed-submission count for this peer/context. |
| `history_saturated` | Capacity is full or this count reached its configured cap; unseen peers can have count zero with this flag set. |

Failure history is independent of nonce-consumption state. It counts partial/empty/malformed solution headers, failed cryptographic checks, and replay. A request without solution headers does not allocate an entry. Successful solutions preserve the count. Nonce-backend failures and downstream application exceptions do not count as caller failures. The updated count is available to the oracle that issues the replacement challenge.

Each fixed window begins at the first failure and expires after 300 seconds by default; further failures do not extend it. Lazy expiry uses a monotonic clock. Defaults retain at most 10,000 digested peer/context keys and cap each count at 1,000,000. Live entries are never evicted for new peers. Saturation is visible so a rule can avoid interpreting a missing count as a clean history; the example oracle chooses its configured maximum difficulty. Its rule otherwise adds one bit per `failures_per_step` failures, capped by `max_difficulty`.

History is local to one middleware instance/process unless the application injects the same instance into several middlewares. Python updates are protected by a thread lock; JavaScript updates are synchronous within one process. Shared Redis nonce state does not share these adaptive counters. Unknown peers share history within the same context. This example rule does not classify agents, authenticate callers, or provide federated learning. Test and tune the cap for your users; peer-based counters can aggregate users behind a proxy or NAT.

See [Python signals tests](../python/tests/test_signals.py) and [Express signals tests](../javascript/tests/signals.test.mjs) for binding, spoofed-header, retention, expiry, saturation, and error-path checks.

## 5. TTL

Default TTL is 300 s (5 min). Shorter TTL reduces retained nonce state and increases challenge re-issuance for slow clients. Every protected request needs a fresh solution. For clients that solve immediately, 60 s is fine. For agent harnesses with offline processing, 600–1800 s.

### Single-use & multi-process state

FastAPI, WSGI, and Express middlewares each create an `InMemoryNonceStore` by default. A valid solution consumes its server nonce before the application runs; reusing it returns a fresh challenge with `error="maxwell_replayed_solution"`. Consumption does not imply the application completed: retries need a fresh challenge, and application-level idempotency remains your responsibility.

The low-level Python `verify_solution(..., nonce_store=None)` and JS `verifySolution` without `nonceStore` retain their stateless behavior. **They permit reuse**; supply a store to enforce single use. In single-use mode expiry is exclusive (`now >= expires_at` rejects); legacy stateless verification retains its inclusive boundary (`now > expires_at` rejects). Neither mode changes the wire format.

In-memory state is safe only when every verifier sharing a signing secret uses the same store in one process. Inject one store if multiple middleware instances use that secret. A restart loses in-memory acceptance state: rotate the secret on restart, or use durable shared state. Multiple workers, hosts, or a load balancer require a shared store. Context binding does not replace replay state.

The in-memory store defaults to 100,000 accepted nonces and a 300-second retention horizon; middleware-created stores size the horizon from `ttl_seconds` / `ttlSeconds`. For explicitly supplied stores, configure the horizon for the longest challenge TTL. Lazy GC removes entries at their expiry on the next access. Capacity exhaustion or an expiry beyond the horizon fails closed; live entries are never evicted. A bounded expiry wheel performs O(1) amortized operations for the configured horizon. Wall-clock rollback fails closed at the store's last observed time.

**Python shared Redis (optional extra):**

```bash
pip install "maxwells-defense[redis]"
```

```python
import os
from maxwells_defense import RedisNonceStore

store = RedisNonceStore.from_url(os.environ["MAXWELL_REDIS_URL"])
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    nonce_store=store,
)
```

**Express shared Redis (optional, application-managed node-redis client):**

```js
import { RedisNonceStore, maxwellsDefense } from "@viridis-security/maxwells-defense/express";

app.use(maxwellsDefense({
    serverSecret: SECRET,
    nonceStore: new RedisNonceStore(redisClient), // already connected by your app
}));
```

Redis 6.2+ consumption atomically checks Redis's clock and runs `SET NX EXAT` at the challenge expiry; no separate expiry command can race. Python and JS use the same `maxwell:nonce:` key prefix by default; isolate independent deployments with a custom prefix. Redis automatically expires keys; client `gc` is a no-op. Redis errors reject acceptance. Configure `maxmemory-policy noeviction`, suitable persistence/failover, and a non-decreasing Redis server clock: key eviction, state loss, a restored stale snapshot, or clock rollback after key expiration can reopen replay. If any of these loses acceptance state, rotate the signing secret before accepting old challenges. Regional consensus is outside this reference's guarantee.

JS low-level verification with an asynchronous store returns a Promise; **await it** before forwarding a request. Express does so automatically. No Redis connection or Redis dependency is required by the default reference implementation.

### Store capacity and fail-closed behavior

The default `InMemoryNonceStore` retains at most **100,000 accepted nonces**. When full, it fails closed: a new valid solution is rejected instead of being accepted without recording its nonce or evicting live state. Failing open would let that solution be replayed until expiry and break single use. Existing consumed nonces remain protected; expired entries free capacity on the next access. See the [Python store](../python/maxwells_defense/nonce_stores.py), [Express store](../javascript/src/maxwell-express.mjs), and [capacity regression](../python/tests/test_replay.py).

Size for peak accepted proof traffic, including proofs consumed before an application failure:

```text
entries needed ≈ accepted requests per second × TTL seconds
100,000 entries / 300-second TTL ≈ 333 accepted requests per second
```

Allow headroom for bursts. An actor who solves enough challenges can fill the store and lock out legitimate callers until entries expire. As a compute-time planning example, [40 local difficulty-18 samples](benchmarks/2026-10-05-compute.json) averaged about **105 ms of process CPU time** per solve on one arm64 Mac using a sequential Python solver. At that measured rate, `100,000 × 0.105 s = 10,500 CPU-seconds ≈ 2.9 CPU-hours`; fitting that work into a 300-second TTL window would require about 35 concurrent CPU equivalents under ideal scaling. This is rough compute-time arithmetic, not a measured distributed load or a bound for other hardware or optimized solvers. The artifact records runtime, method, raw samples, source hashes and the tested commit.

For internet-facing endpoints:

- Pass a shared Redis store to every worker/host; size Redis memory for peak accepted traffic and use `noeviction` with suitable persistence/failover. Redis shares replay state but still has finite capacity and can reject writes.
- Apply upstream IP/rate limits before Maxwell to bound challenge issuance and acceptance traffic; account for legitimate users behind shared addresses.
- Use a shorter TTL where client solve/retry latency allows it. This reduces retained state, but leaves less time for slower callers.
- Monitor store rejection counts and occupancy. Alert on rising storage failures before legitimate requests are locked out.

A full store is observable separately from replay without changing the API. Direct consumption raises `NonceStoreUnavailable("nonce store capacity reached")`; verification of an already-consumed solution raises `ReplayedSolution`. Python middleware reports `error="NonceStoreUnavailable"` for storage failures; Express reports `error="nonce store capacity reached"` for this capacity error. Both report `error="maxwell_replayed_solution"` for replay. Count these rejection reasons in access metrics; instrument `consume` if Python metrics must distinguish capacity from other storage failures, since `NonceStoreUnavailable` also covers an invalid retention horizon or an unavailable Redis backend. The reference supplies no built-in metrics counter. See the [error hierarchy](../python/maxwells_defense/errors.py) and [HTTP rejection handling](../python/maxwells_defense/middleware.py).

## 6. Client integration

A protected endpoint returns `401` by default with a JSON body containing the challenge. The client solves and re-requests with the challenge and solution in headers.

### HTTP response mode

FastAPI/WSGI accept `challenge_status_code=429, retry_after_seconds=1`; Express accepts `challengeStatusCode: 429, retryAfterSeconds: 1`. This alternative returns `429 Too Many Requests` with a [delta-seconds `Retry-After`](https://httpwg.org/specs/rfc9110.html#field.retry-after) header. The retry interval must be a nonnegative integer; zero permits an immediate solve/retry. Keep it shorter than the challenge TTL, allowing time for solving. The existing default remains `401` without `Retry-After`; selecting a different default requires Justin's review.

Both modes emit `X-Maxwell-Challenge` containing the same JSON challenge as the response body, plus `X-Maxwell-Provider`. Header JSON escapes non-ASCII context characters without changing the parsed wire fields. Applications using CORS must expose these headers if browser clients read them across origins.

```python
app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    challenge_status_code=429,
    retry_after_seconds=1,
)
```

```js
app.use(maxwellsDefense({
    serverSecret: SECRET,
    challengeStatusCode: 429,
    retryAfterSeconds: 1,
}));
```

**JavaScript (browser or Node 18+):**

```js
import { fetchWithMaxwell } from "@viridis-security/maxwells-defense";

const res = await fetchWithMaxwell("/api/protected", { method: "POST" });
```

`fetchWithMaxwell` auto-retries once with a solved challenge when a `401` or `429` contains both `X-Maxwell-Provider` and a JSON challenge. It honors delta-seconds `Retry-After` on Maxwell `429` responses, counting solve time toward the delay. Ordinary authentication failures and rate-limit responses pass through unchanged. HTTP-date retry policies are left to application-specific clients.

**Python (httpx):**

```python
import httpx
from maxwells_defense.core import Challenge, Solution, solve_challenge

with httpx.Client() as c:
    r = c.get("https://api.example.com/protected")
    if r.status_code == 401 and r.headers.get("X-Maxwell-Provider"):
        body = r.json()
        challenge = Challenge.from_dict(body["challenge"])
        solution = solve_challenge(challenge)
        r = c.get(
            "https://api.example.com/protected",
            headers={
                "X-Maxwell-Challenge": json.dumps(challenge.to_dict()),
                "X-Maxwell-Solution":  json.dumps(solution.to_dict()),
            },
        )
```

**Agent harnesses (raw):** implement the same loop. The wire format is documented in the README; the JS↔Python interop test (`javascript/tests/interop.test.mjs`) is the canonical contract.

## 7. Observability

Every issued challenge ships `X-Maxwell-Provider: viridis-security.com`. Every challenge body contains a `spec` link. Both make it easy to:

- Tag PoW-gated requests in your access logs.
- Distinguish legit agent retries (which carry the challenge+solution headers) from fresh attacker probes (which don't).
- Build dashboards on challenge issuance rate, average solve time, and rejection reasons.

## 8. What this defense does *not* do

- **It does not authenticate users.** Maxwell's Defense requires computational work, not identity credentials. Bolt your normal auth on after.
- **It does not protect against attackers with cheap PoW** (e.g., ASIC miners reusing SHA-256 hardware). Solve time depends on the implementation and hardware; the search-query model does not establish a wall-time or deployment-cost bound. Combine with rate limiting for hard cutoffs.
- **It does not replace input validation.** Solved challenges still produce requests that hit your application logic. Validate inputs as usual.
- **It does not protect WebSockets after the initial handshake.** Apply Maxwell at connection-open; renew per-message at high difficulty would be hostile.

## 9. Hosted tier

`HostedDifficultyOracle` is not implemented or exported by this reference. The proposed `/v1/maxwell/difficulty` client, local fallback behavior, and hosted receipt/parameter contract require the separate hosted implementation audit (WP-6); they are unavailable here. Use a local static oracle or the bounded example above. This work does not promise a release date or free hosted query allowance.

For hosted integration, ask [Viridis Security](mailto:viridissecurity1@gmail.com) to confirm the documented endpoint contract and your account's Maxwell entitlement. Scan-service signup alone does not establish access to Maxwell challenge generation. The reference SHA-256 implementation remains separate from the advertised hosted Argon2id, amplification, and receipt features.

## 10. Version pinning and typing

The 0.x API may change between releases. Use an exact released version and update deliberately after running your integration tests. The source declares `0.2.0` as a release candidate. The following pins are for use after that version is published; this preparation PR does not publish it. Until then, install the reviewed source checkout with `pip install -e ./python` and use the JavaScript source locally:

```bash
pip install "maxwells-defense==0.2.0"
# When using optional shared Redis state:
pip install "maxwells-defense[redis]==0.2.0"
npm install --save-exact @viridis-security/maxwells-defense@0.2.0
```

Avoid floating Git branches and broad version ranges for production installs. Commit the application's dependency lock file. Upgrade the server and clients with the interop and replay suites before choosing a new pin; this source change does not publish a release.

The Python wheel includes a PEP 561 `py.typed` marker so type checkers discover the package's existing inline annotations. The packaging regression builds a wheel locally and checks that the marker ships inside it.
