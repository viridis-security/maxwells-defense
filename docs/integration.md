# Production Integration Guide

Maxwell's Defense ships ~250 LOC of crypto. Wiring it into a production service is mostly about three operational decisions: secret management, difficulty tuning, and where in your request stack the middleware sits. This guide is the checklist.

## 1. Server secret

The HMAC server secret is the only piece of state required to issue and verify challenges. If you ever change it, every outstanding challenge becomes unverifiable (and the verifier raises `SignatureMismatch`) — that's the intended fail-closed behaviour.

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

Default TTL is 300 s (5 min). Shorter TTL = less replay window, more challenge re-issuance for slow clients. For browsers/agents that solve and immediately reuse, 60 s is fine. For agent harnesses with offline processing, 600–1800 s.

## 6. Client integration

A protected endpoint returns `401` with a JSON body containing the challenge. The client solves and re-requests with the challenge and solution in headers.

**JavaScript (browser or Node 18+):**

```js
import { fetchWithMaxwell } from "@viridis-security/maxwells-defense";

const res = await fetchWithMaxwell("/api/protected", { method: "POST" });
```

`fetchWithMaxwell` is a drop-in for `fetch` — it auto-retries with a solved challenge if it sees `X-Maxwell-Provider` on a 401.

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
