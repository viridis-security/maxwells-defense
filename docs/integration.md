# Production Integration Guide

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

## 4. Context binding

The `context_id` field binds a challenge to a specific (route, agent identity, etc.) combination. The default middleware binds to `host + path`. For tighter binding:

```python
class MyDifficultyOracle:
    def __call__(self, context_id: str, signals):
        # Custom difficulty per route, agent type, etc.
        return ...

app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    difficulty_oracle=MyDifficultyOracle(),
)
```

To bind a challenge to a specific authenticated user, derive the `context_id` to include a hash of their session id. Solutions issued to user A can't then be replayed by user B.

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

- **It does not authenticate users.** Maxwell's Defense is rate-limiting by energy expenditure, not identity. Bolt your normal auth on after.
- **It does not protect against attackers with cheap PoW** (e.g., ASIC miners reusing SHA-256 hardware). At `d ≤ 24`, well-funded attackers solve in tenths of a second. The asymmetry holds in CPU expenditure ratio, not absolute cost — combine with rate limiting for hard cutoffs.
- **It does not replace input validation.** Solved challenges still produce requests that hit your application logic. Validate inputs as usual.
- **It does not protect WebSockets after the initial handshake.** Apply Maxwell at connection-open; renew per-message at high difficulty would be hostile.

## 9. Hosted tier

When you want the difficulty oracle to learn from cross-site attack patterns, swap the local oracle for the hosted one:

```python
from maxwells_defense.middleware import FastAPIMaxwellMiddleware
from maxwells_defense.core import HostedDifficultyOracle  # 0.2.0+

app.add_middleware(
    FastAPIMaxwellMiddleware,
    server_secret=SECRET,
    difficulty_oracle=HostedDifficultyOracle(
        endpoint="https://mcp.viridis-security.com/v1/maxwell/difficulty",
        api_key=os.environ["VIRIDIS_API_KEY"],
    ),
)
```

`HostedDifficultyOracle` lands in v0.2.0. Pricing: 100K queries/mo free; `mcp.viridis-security.com`.
