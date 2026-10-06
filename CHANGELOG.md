<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

Notable changes are grouped by version and change type. The 0.x API may change
between releases; review the upgrade notes before changing an exact version pin.

## [0.2.0] - Unreleased

Prepared for **0.2.0**; release date pending. These are source changes since the
`v0.1.0` tag, including [PR #9](https://github.com/viridis-security/maxwells-defense/pull/9),
[PR #10](https://github.com/viridis-security/maxwells-defense/pull/10),
[PR #11](https://github.com/viridis-security/maxwells-defense/pull/11), and
[PR #12](https://github.com/viridis-security/maxwells-defense/pull/12).
This preparation does not establish a `v0.2.0` tag or publication to PyPI or npm.

### Security

- FastAPI, WSGI, and Express middleware now default to single-use challenges.
  A valid solution consumes its server nonce before the application runs;
  replay returns a fresh challenge with `error="maxwell_replayed_solution"`.
  Capacity exhaustion fails closed without evicting live acceptance state.
  [Single-use contract and tests](python/tests/test_replay.py).
- Added bounded in-memory nonce state and optional shared Redis state. Verifiers
  sharing a signing secret must share the same store. Multiple workers or hosts
  require shared state; restarting an in-memory deployment requires secret
  rotation or durable shared state. Redis requires 6.2+, appropriate durability,
  and `noeviction`. [Deployment requirements](docs/integration.md#single-use--multi-process-state).

### Added

- Seven [top-level Python exports](python/maxwells_defense/__init__.py):
  `NonceStore`, `InMemoryNonceStore`, `RedisNonceStore`, `ReplayedSolution`,
  `NonceStoreUnavailable`, `FailedAttemptHistory`, and
  `FailedAttemptDifficultyOracle`. Redis support is an optional `redis` extra;
  default operation has no required external service.
- Store-capacity sizing and fail-closed lockout risks are documented, with
  retained local compute-time samples backing the planning arithmetic.
  [Capacity guide](docs/integration.md#store-capacity-and-fail-closed-behavior).
- Six [JavaScript `/express` exports](javascript/src/maxwell-express.mjs):
  `InMemoryNonceStore`, `RedisNonceStore`, `ReplayedSolution`,
  `NonceStoreUnavailable`, `FailedAttemptHistory`, and
  `FailedAttemptDifficultyOracle`. The client module's exports are unchanged.
- Optional context factories and bounded local failure history. Oracles receive
  read-only signals for the transport peer, method, path, failed attempts, and
  history saturation. Proxy headers do not establish caller identity.
  [Context and signal guide](docs/integration.md#4-context-binding-and-local-signals).
- Configurable `429` challenges with delta-seconds `Retry-After`, plus
  `X-Maxwell-Challenge` response headers matching the JSON challenge.
  [HTTP configuration](docs/integration.md#http-response-mode).
- Python `py.typed` metadata and exact version-pinning guidance. Version
  declarations and documented pins are aligned for 0.2.0 preparation, with
  drift checks and isolated built-wheel coverage.
  [Packaging tests](python/tests/test_packaging.py).
- Since `v0.1.0`, before PRs #9–#12: added DCO and secret-scan workflows,
  release build/publication workflows, grouped Dependabot updates, issue forms,
  and a PR template. Workflow presence does not establish a package publication.
- Added [security reporting](SECURITY.md), [conduct](CODE_OF_CONDUCT.md), and
  [trademark guidance](TRADEMARKS.md) since `v0.1.0`.

### Changed

- **Upgrade:** every protected middleware request needs a fresh solution,
  including a retry after the downstream application fails. Application-level
  idempotency remains the caller's responsibility. Low-level Python
  `verify_solution(..., nonce_store=None)` and JavaScript `verifySolution`
  without `nonceStore` remain stateless and **replayable within the TTL**.
- Single-use expiry rejects at `now >= expires_at`; legacy stateless verification
  retains its `now > expires_at` boundary. The challenge and solution wire
  formats and the [original 17 invariant assertions](python/tests/test_invariants.py)
  are unchanged; test imports are tidied for Ruff.
- Default challenge status remains `401`; `429` is opt-in. Default difficulty
  remains static at 18. Adaptive rules and caller-specific binding are opt-in;
  failure history stays local even when nonce acceptance uses Redis.
- JavaScript middleware returns a handled Promise and supports asynchronous
  nonce stores. Direct callers must await `verifySolution` when a configured
  store is asynchronous; stateless verification remains synchronous.
- Nonempty signing secrets shorter than 32 bytes now emit warnings without
  exposing key material. Empty secrets still fail. Length alone does not
  establish entropy. [Secret guidance](docs/integration.md#1-server-secret).
- Public and package copy now separates the classical random-oracle search-cost
  argument from the conditional T-IB-09 research model. The model declares one
  external asymmetry axiom; its saved report concerns arithmetic corollaries
  with explicit hypotheses. No new Lean or Aristotle run is claimed.
  [Exact source, report, and assumptions](THEOREMS.md#t-ib-09).
- Hosted access and feature claims are scoped separately from this SHA-256
  reference. `HostedDifficultyOracle`, hosted Argon2id parameters, receipt
  lifecycle, and account entitlements are not supplied by this release.
  [Hosted integration status](docs/integration.md#9-hosted-tier).
- Expanded CI coverage for replay, HTTP, adaptive signals, cross-language
  interoperability, and workflow syntax; updated GitHub Actions dependencies.
- Expanded [contribution guidance](CONTRIBUTING.md) and clarified
  [NOTICE](NOTICE) attribution. The SDK remains licensed under
  [Apache-2.0](LICENSE).

### Fixed

- The wheel typing-marker regression uses an isolated build backend instead of
  ambient distro-patched setuptools. Unavailable backend dependencies skip with
  a clear reason; package defects and missing typing metadata still fail.
  [Isolated build tests](python/tests/test_packaging.py).
- Ruff import classification is explicit for the Python package, with stale
  unused imports removed from tests.

- Express 4 errors from context factories, difficulty oracles, and unexpected
  nonce-store failures reach `next(error)`; backend failures do not count as
  caller failures. [Express signal tests](javascript/tests/signals.test.mjs).
- Unicode contexts use ASCII-safe challenge headers in server responses and
  fetch retries. The client recognizes Maxwell `401` and `429` responses,
  honors supported retry delays, and preserves ordinary authentication and
  rate-limit responses. [HTTP tests](javascript/tests/http.test.mjs) and
  [fetch/replay tests](javascript/tests/replay.test.mjs).
- Guarded the repaired `signal-watch` workflow expression with an actionlint
  regression and removed unnecessary token permissions.
  [Workflow check](scripts/check-signal-watch.sh).

### Removed

- Removed temporary execution notes from the package root.

## [0.1.0]

### Added

- Initial Apache-2.0 SHA-256 proof-of-work reference: HMAC-bound challenges,
  solution verification and solving helpers, a static/pluggable difficulty
  oracle, FastAPI/WSGI/Express integrations, and a JavaScript fetch wrapper.
- Seventeen Python invariant tests, JavaScript/Python interoperability tests,
  integration examples, and initial documentation.

[0.2.0]: https://github.com/viridis-security/maxwells-defense/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/viridis-security/maxwells-defense/tree/v0.1.0
