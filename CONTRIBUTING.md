# Contributing

Maxwell's Defense is small and focused. Contributions land fast if they fit the design; PRs that don't, we'll discuss in an issue first.

## What we want

1. **Difficulty-oracle rules from real-world deployments.** If you've tuned `difficulty(context)` against actual agent traffic and the rule generalizes, file an issue with the rule + the traffic shape it addresses. We're building a catalog of these as part of the federated-difficulty effort.
2. **Language ports of the client solver.** Today: Python (server + solver), JavaScript (server + client). We want Go, Rust, and Swift clients with bit-exact wire compatibility. Use the JS↔Python interop test as the contract.
3. **Bug reports with reproducible failure of any MX-INV-* invariant.** See [THEOREMS.md § Falsifiability](THEOREMS.md#falsifiability) for the list.
4. **Documentation improvements.** Especially the integration guide and the THEOREMS file — explain the asymmetry better than we did.

## What we don't want

- **Exploit code, offensive tooling, or attack examples.** This library is the defense primitive. Public API is lexically lint-checked to reject names containing `attack`, `exploit`, `bypass`, `payload`, etc. If your contribution needs those words, it belongs in a different repo.
- **Network calls from the default reference implementation.** The client and server defaults make zero outbound calls. The optional, explicitly configured Redis nonce store connects only to the application's shared state backend; see [the single-use deployment contract](docs/integration.md#single-use--multi-process-state). The hosted tier at `mcp.viridis-security.com` is a separate codebase that consumes this library.
- **Cryptographic primitive substitutions without discussion.** SHA-256 is chosen for ubiquity and constant-time native implementations everywhere. If you have a reason to swap (BLAKE3, etc.), file an issue first.

## Workflow

```bash
git clone https://github.com/viridis-security/maxwells-defense
cd maxwells-defense

# Python
cd python
pip install -e ".[test]"
pytest tests/ -v        # original 17 tests and replay regressions must pass

# JavaScript
cd ../javascript
node tests/interop.test.mjs   # must finish with [ok] on each line
node tests/replay.test.mjs    # single-use regression suite
```

PRs must keep the 17 original invariant tests and all replay regressions green. New invariants get new named tests with an `MX-INV-*` reference comment.

## Security disclosures

If you find a vulnerability in Maxwell's Defense itself (not in a deployment using it), email [viridissecurity1@gmail.com](mailto:viridissecurity1@gmail.com) with `[security] maxwells-defense` in the subject. We'll respond within 72 hours. We follow standard 90-day responsible-disclosure.

Do not file security issues in the public tracker.

## License

By submitting a PR you agree to license your contribution under Apache-2.0.

## Sign your commits (DCO)

Pull requests from forks need a `Signed-off-by` line on every commit, matching the commit author's email:

    Signed-off-by: Your Name <you@example.com>

`git commit -s` adds it, and `git rebase --signoff origin/main` fixes an existing branch. Signing off
certifies the Developer Certificate of Origin 1.1 (https://developercertificate.org): you wrote the
change, or you have the right to submit it under this repository's license. The DCO check blocks
unsigned commits.

## License of contributions

Contributions are licensed under the same license as the files they change (see `LICENSE`), with no
additional terms. Don't submit work you can't license that way.

## Never commit

Credentials, API keys, private keys, `.env` files, customer or partner data, or wallet files. The secret
scan blocks known key formats. If you find a leaked secret, report it privately as described in
`SECURITY.md`.

## Names and marks

The license does not cover Viridis names, logos or certification marks. See `TRADEMARKS.md`.
