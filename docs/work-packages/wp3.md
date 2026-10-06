<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP-3: transport context and adaptive signals

Branch: `codex/wp-3-adaptive-signals`, based on WP-4 commit
`075fab7172cbce45fed4e060a2391cdd855a3b1c`. This prepares a separate reviewed PR.

## Invariants satisfied

- [x] INV-3.1: optional context factories can bind a challenge to the transport peer or an identity established by the application. Default Python `host + path` and Express `host + originalUrl` bindings remain unchanged. Proxy headers and Express `req.ip` are not used as transport identity.
- [x] INV-3.2: every middleware oracle invocation receives `remote_addr`, `method`, `path`, `failed_attempts`, and `history_saturated`. Failed submissions update bounded local history before issuing the replacement challenge. New Python and Express tests exercise these signals.
- [x] INV-3.3: adaptive policy is explicitly opt-in; the default remains static. The capped `FailedAttemptDifficultyOracle` example escalates from actual failure signals. Cross-site learning and `HostedDifficultyOracle` are unavailable in this reference, pending the separate WP-6 implementation/contract audit.
- [x] INV-3.4: contradictory immediate/free hosted challenge-generation CTAs and unsupported quotas are removed. The working local reference is the install path; hosted access requires confirmation of endpoint entitlements and limits.

## Acceptance output

Local runtime: Python 3.11.5, pytest 8.3.3, bundled Node 24. Dependencies were installed into an ignored local environment without network access:

```text
.venv/bin/python -m pip install --no-build-isolation --no-deps -e './python[test]'
Successfully installed maxwells-defense-0.1.0

.venv/bin/python -m pytest python/tests/ -v
collected 108 items
107 passed, 1 skipped in 0.35s
```

All 17 original invariant tests passed and remain unmodified. The one skip is the optional external Redis-server integration; fake-Redis logic tests passed. The full suite includes the inherited actual-wheel typing-marker check. WP-3 adds 39 Python cases covering both middleware variants, peer/context isolation, spoofed headers, malformed headers, HMAC failure, replay, retention after success, backend/application failures, TTL/capacity/count saturation, threaded updates, and the adaptive example.

```text
node tests/interop.test.mjs
[ok] JS roundtrip verified
[ok] tampered difficulty rejected (SignatureMismatch)
[ok] wrote /tmp/maxwell-interop.json for Python verifier

node tests/replay.test.mjs
[ok] in-memory and Redis parity: one acceptance, independent contexts
[ok] lazy GC handles out-of-order expiry, wrap and clock rollback
[ok] invalid context does not consume valid work
[ok] capacity never evicts live state; expiry recovers capacity
[ok] shared Redis state has one winner and fails closed on errors or expiry
[ok] stateless behavior unchanged; single-use expiry is exclusive
[ok] Express defaults and asynchronous shared store reject replay before forwarding

node tests/http.test.mjs
[ok] default 401 and configurable 429 with Retry-After
[ok] ASCII challenge headers match JSON bodies in both HTTP modes
[ok] fetch solves Maxwell 401/429; ordinary auth/rate limits stay readable and unchanged
[ok] fetch honors delta-seconds Retry-After before a single retry
[ok] short keys warn without secret disclosure; recommended keys stay quiet

node tests/signals.test.mjs
[ok] default binding preserved; raw socket peer overrides spoofed proxy headers/req.ip
[ok] optional peer binding rejects another peer without consuming original nonce
[ok] malformed/invalid/replayed submissions count; peer/context isolation and success retention
[ok] nonce backend and downstream application failures do not affect caller history
[ok] fixed TTL, bounded capacity/count, conservative saturation, rollback and recovery
[ok] invalid factory rejection, example escalation/cap and one-argument callback compatibility

Python cross-language verification
[ok] Python accepted the JS-issued/solved fixture

ruff check python/maxwells_defense/core.py python/maxwells_defense/middleware.py python/maxwells_defense/__init__.py python/maxwells_defense/failure_history.py python/tests/test_signals.py
exit 0, no diagnostics

PYTHONDONTWRITEBYTECODE=1 ../wp1/.venv/bin/mypy --check-untyped-defs python/maxwells_defense
Success: no issues found in 6 source files

bash scripts/check-signal-watch.sh /private/tmp/maxwell-wp4-actionlint-1.7.12/actionlint
[ok] signal-watch valid; invalid job-level env guard rejected

git diff --check
exit 0, no diagnostics

gitleaks protect --staged --redact --no-banner --config .gitleaks.toml
scanned ~52762 bytes (52.76 KB)
no leaks found

actionlint -shellcheck= -pyflakes= .github/workflows/ci.yml
exit 0, no diagnostics
```

## Review and limits

The parent agent reviewed the Python/JS counters, middleware, and copy and found no actionable correctness issue. Unknown peers at capacity receive `history_saturated=true` even when their retained count is zero; the example chooses its configured cap. Successful verification does not reset failure history. Invalid/empty factory results fail before challenge issuance. Downstream application exceptions and backend failures do not create caller-failure history.

History is per-process and per middleware instance by default, independent of the nonce protocol. Python uses a lock; Node updates are synchronous without an await. Applications can inject one history instance into several middleware instances. Redis nonce sharing does not federate these counters. Windows start at the first failure, expire after the configured TTL, and are not extended by later attempts. Live entries are never evicted; only digested peer/context keys are retained. Proxy/NAT peers can aggregate callers, and unavailable transport addresses aggregate by context. Applications must establish authenticated identity or trusted proxy policy themselves.

The inherited thermodynamic/Aristotle copy is corrected separately by WP-2 PR #9. This branch's earlier README/package headers are not confirmation of those claims: review the combined WP-2 copy before any release or publication. WP-2's Justin copy gate remains separate. Hosted parameters, receipts, pricing, and endpoint access remain unconfirmed here; advertised hosted design is not asserted to have passed these reference tests.

Out of scope: no hosted endpoint calls, cross-site learning, private SDK contract acceptance, production deployment, payments/billing, outreach, release publication, merge, or Aristotle execution. This work does not change the 401 default awaiting Justin's WP-4 decision.
