#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# INV-4.4: syntax checks only; never execute an event or contact the webhook.
set -euo pipefail

validator="${1:-actionlint}"
command -v "$validator" >/dev/null
cd "$(dirname "$0")/.."

"$validator" -shellcheck= -pyflakes= .github/workflows/signal-watch.yml
diagnostics="$(mktemp)"
trap 'rm -f "$diagnostics"' EXIT
if "$validator" -shellcheck= -pyflakes= \
    tests/workflow-fixtures/invalid-job-env.yml >"$diagnostics" 2>&1; then
    echo 'Expected actionlint to reject the historical job-level env guard' >&2
    exit 1
fi
grep -Fq 'context "env" is not allowed here' "$diagnostics"
echo '[ok] signal-watch valid; invalid job-level env guard rejected'
