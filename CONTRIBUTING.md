# Contributing

Maxwell's Defense is small and focused. Contributions land fast if they fit the design; PRs that don't, we'll discuss in an issue first.

## What we want

1. **Difficulty-oracle rules from real-world deployments.** If you've tuned `difficulty(context)` against actual agent traffic and the rule generalizes, file an issue with the rule + the traffic shape it addresses. We're building a catalog of these as part of the federated-difficulty effort.
2. **Language ports of the client solver.** Today: Python (server + solver), JavaScript (server + client). We want Go, Rust, and Swift clients with bit-exact wire compatibility. Use the JS↔Python interop test as the contract.
3. **Bug reports with reproducible failure of any MX-INV-* invariant.** See [THEOREMS.md § Falsifiability](THEOREMS.md#falsifiability) for the list.
4. **Documentation improvements.** Especially the integration guide and the THEOREMS file — explain the asymmetry better than we did.

## What we don't want

- **Exploit code, offensive tooling, or attack examples.** This library is the defense primitive. Public API is lexically lint-checked to reject names containing `attack`, `exploit`, `bypass`, `payload`, etc. If your contribution needs those words, it belongs in a different repo.
- **Network calls from the reference implementation.** The client and server reference implementations make zero outbound calls. The hosted tier at `mcp.viridis-security.com` is a separate codebase that consumes this library.
- **Cryptographic primitive substitutions without discussion.** SHA-256 is chosen for ubiquity and constant-time native implementations everywhere. If you have a reason to swap (BLAKE3, etc.), file an issue first.

## Workflow

```bash
git clone https://github.com/viridis-security/maxwells-defense
cd maxwells-defense

# Python
cd python
pip install -e ".[test]"
pytest tests/ -v        # must show 17/17 green

# JavaScript
cd ../javascript
node tests/interop.test.mjs   # must finish with [ok] on each line
```

PRs must keep both test suites green. New invariants get new named tests with an `MX-INV-*` reference comment.

## Security disclosures

If you find a vulnerability in Maxwell's Defense itself (not in a deployment using it), email [viridissecurity1@gmail.com](mailto:viridissecurity1@gmail.com) with `[security] maxwells-defense` in the subject. We'll respond within 72 hours. We follow standard 90-day responsible-disclosure.

Do not file security issues in the public tracker.

## License

By submitting a PR you agree to license your contribution under Apache-2.0.
