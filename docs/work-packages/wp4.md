<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP-4 review notes

Status: merged in PR #11; the combined reference changes in PRs #9–#12 are on main. The 401-versus-429 default remains Justin's unresolved choice. This implementation preserves 401; elapsed time is not treated as approval to change it. This historical work-package acceptance records no deployment, payment, billing mutation, outreach, submission, or release publication.

## Invariants and implementation

- INV-4.1: FastAPI/WSGI accept `challenge_status_code=429` and `retry_after_seconds`; Express mirrors these as `challengeStatusCode` / `retryAfterSeconds`. The alternative emits 429 with nonnegative delta-seconds `Retry-After`. Default 401 has no retry header. Fetch solves Maxwell 401 and 429 once, preserves ordinary auth/rate-limit responses, and honors supported retry delays. HTTP-date or unusually long policies are returned to the caller without an automatic retry.
- INV-4.2: Both HTTP modes emit `X-Maxwell-Challenge` matching the JSON body. Header serialization escapes Unicode to ASCII without altering parsed fields.
- INV-4.3: Nonempty keys below 32 bytes warn at Python issuance/middleware setup and once per loaded Node module; warnings disclose no key material. Empty keys still error. No compatibility break was imposed on short-key callers.
- INV-4.4: The workflow was already repaired, as detailed below. Syntax checks and a negative expression fixture prevent the historical mistake from returning.
- INV-4.5: Explicit package data ships `maxwells_defense/py.typed`. A regression builds the actual wheel in a temporary source copy and checks the marker. The integration guide documents exact 0.x pins and deliberate upgrades.

Each task has its own signed conventional commit with tests. The original invariant/replay suites remain unchanged. New package-build tools are test-only dependencies, not runtime dependencies.

## signal-watch history and validation

Commit `25a56d27265d35d4e0961454f5b26f70b401e9ac` moved the invalid job-level `env` guard to the step level. It did not remove the workflow. The current source already passed [actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) before this change. The workflow remains present; this WP denies unnecessary GitHub token permissions, uses the existing environment variable for the webhook, and corrects the comment that treated every event as a human signal.

`scripts/check-signal-watch.sh` validates the real workflow and requires rejection of a deliberate negative fixture using the historical invalid job-level expression. CI pins the official Linux validator release and its archive checksum. Validation disables optional ShellCheck/Pyflakes integrations, which were unavailable locally; it checks GitHub Actions syntax and expression contexts. No event or webhook is executed by the checks.

```text
bash scripts/check-signal-watch.sh /private/tmp/maxwell-wp4-actionlint-1.7.12/actionlint
[ok] signal-watch valid; invalid job-level env guard rejected
exit 0
```

## Acceptance

```text
Python 3.11.5 / pytest 8.3.3:
python -m pytest python/tests/ -v
68 passed, 1 skipped in 0.32s
The skipped case is optional dedicated local Redis; no server was configured.
All 17 original tests and WP-1 replay regressions passed.
The packaging case built a wheel and confirmed maxwells_defense/py.typed.

Bundled Node v24.19.0:
node javascript/tests/interop.test.mjs
[ok] JS roundtrip verified
[ok] tampered difficulty rejected (SignatureMismatch)
[ok] wrote /tmp/maxwell-interop.json for Python verifier
node javascript/tests/replay.test.mjs
All in-memory/shared-state/replay/expiry/Express cases passed.
node javascript/tests/http.test.mjs
[ok] default 401 and configurable 429 with Retry-After
[ok] ASCII challenge headers match JSON bodies in both HTTP modes
[ok] fetch solves Maxwell 401/429; ordinary auth/rate limits stay readable and unchanged
[ok] fetch honors delta-seconds Retry-After before a single retry
[ok] short keys warn without secret disclosure; recommended keys stay quiet
Python verification of the JS artifact:
[ok] cross-language verified

ruff check on changed Python modules and new tests: exit 0.
mypy --check-untyped-defs python/maxwells_defense:
Success: no issues found in 5 source files
actionlint 1.7.12 (ci.yml and signal-watch.yml): exit 0, no diagnostics.
bash -n scripts/check-signal-watch.sh: exit 0.
git diff --check: exit 0.
```

The successful type check used the existing WP-1 test environment, which has the optional Redis typing dependency; no runtime dependency was added for it. Workflow checks performed static validation only. The original acceptance above was recorded while this PR was stacked on WP-1. Full main-targeted CI passed after retargeting and integration; [PR #11](https://github.com/viridis-security/maxwells-defense/pull/11) retains those checks.

## Out of scope and assumptions

Public releases, changing the default HTTP status, and production configuration require their separate review/authority. The retry interval is a client hint; applications should keep it below the challenge TTL and allow solve time. Existing single-use state assumptions from WP-1 apply. The merged [WP-2 notes](wp2/CODEX_NOTES.md) explain the bounded proof claims; the merged [WP-3 notes](wp3.md) cover transport context and adaptive signals. Hosted implementation/entitlements remain unconfirmed by these reference tests. This branch does not rerun Aristotle or claim fresh formal verification.

Attribution: Codex (OpenAI), implementing Justin's 2026-10-05 handoff. The workflow audit used official actionlint artifacts; no Aristotle work was performed.
