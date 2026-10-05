<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP-4 review notes

## signal-watch history and validation

Commit `25a56d27265d35d4e0961454f5b26f70b401e9ac` moved the invalid job-level `env` guard to the step level. It did not remove the workflow. The current source already passed [actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) before this change. The workflow remains present; this WP denies unnecessary GitHub token permissions, uses the existing environment variable for the webhook, and corrects the comment that treated every event as a human signal.

`scripts/check-signal-watch.sh` validates the real workflow and requires rejection of a deliberate negative fixture using the historical invalid job-level expression. CI pins the official Linux validator release and its archive checksum. Validation disables optional ShellCheck/Pyflakes integrations, which were unavailable locally; it checks GitHub Actions syntax and expression contexts. No event or webhook is executed by the checks.

```text
bash scripts/check-signal-watch.sh /private/tmp/maxwell-wp4-actionlint-1.7.12/actionlint
[ok] signal-watch valid; invalid job-level env guard rejected
exit 0
```
