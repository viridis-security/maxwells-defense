<!-- SPDX-License-Identifier: Apache-2.0 -->

# WP-2 review notes

Status: draft for Justin's final-copy sign-off. Branch/PR preparation only; no merge, deployment, payment, outreach, submission, account mutation, Aristotle request, or fresh Lean check.

## Evidence and scope

The README, THEOREMS, Python package README/docstrings/descriptions, and JavaScript package description now distinguish the classical random-oracle search-cost argument from the conditional dissipation model. Public claims link to exact copied source/report artifacts and implementation/tests. The T-IB-02 section is unchanged. The optional new PoW lemma is future work.

The canonical T-IB-09 source and saved Aristotle output source are byte-identical (`b3b1b7358d955449b24b7d9a643d4d0f0ac7606ae3af577a2554a213efece365`). Its source header says `STUB` and names v4.24.0; the saved report says the corollaries compiled, and the saved output project selects v4.28.0. The badge therefore says **conditional model · 1 axiom**, rather than asserting a fresh checking result. The report says the four proofs do not invoke the external axiom; the first three assume the amplified energy bounds explicitly. That is more precise than claiming all four depend on the axiom.

The axiom quantifies over arbitrary real `E_atk` without a premise that it represents a valid defense execution. Instantiating that variable at zero conflicts with the profile's positive `E_legit` and `M ≥ 1`. The public copy explains that the declaration cannot establish a physical guarantee. Options for a separate research change are to remove the unused axiom or replace it with a properly scoped defense-validity hypothesis, then commission an independent proof/model audit. This WP preserves the source bytes and makes no such change.

## Remaining review and external actions

- Justin must approve the final public wording, as required by the handoff. The draft is prepared for that decision.
- GitHub repository metadata/description and topic still advertise `Aristotle-verified` according to kickoff inspection. Repository metadata is outside branch/PR authority. An authorized owner must replace that label with bounded wording after copy approval; this PR cannot perform that external mutation.
- Hosted Argon2id, receipt lifecycle, amplification behavior, pricing/CTA contradictions, adaptive signals, and replay protection are assigned to other WPs. This documentation change does not audit or confirm those implementations. The changed amplification sentence qualifies only the physical/economic interpretation.
- Evidence snapshots retain historical comments/report wording for provenance. They are not current product claims or a substitute for a new checking receipt.

## Local acceptance

```text
Python 3.11.5, pytest 8.3.3; offline editable install with existing local tooling:
python -m pip install --no-build-isolation --no-deps -e './python[test]'
Successfully installed maxwells-defense-0.1.0
python -m pytest python/tests/ -v
22 passed in 0.03s (17 original tests unchanged + 5 documentation cases)

Bundled Node v24.19.0; node javascript/tests/interop.test.mjs:
[ok] JS roundtrip verified
[ok] tampered difficulty rejected (SignatureMismatch)
[ok] wrote /tmp/maxwell-interop.json for Python verifier
Python verification of that JS artifact:
[ok] cross-language verified

ruff 0.0.272 check: new tests and changed Python modules passed (exit 0).
git diff --check: passed (exit 0).
rg -ni 'verified|proved|proven' README.md THEOREMS.md:
Only the hosted provenance sentence and the explicitly historical checking
report/provenance paragraph matched; neither asserts proved thermodynamics.
```

The first network-dependent install failed because restricted DNS could not resolve the package registry. The offline install and suite above passed. System Node v18.18.0 lacks the global `crypto` used by the existing interop test; its first run failed before verification. The unchanged suite passed with bundled Node v24.19.0. Ruff's installed version has no `format --check`; lint and whitespace checks passed. None of these tooling limitations is represented as fresh formal-proof evidence.

Attribution: documentation and regression checks prepared by Codex (OpenAI) from Justin's 2026-10-05 handoff; no Aristotle work was performed in this WP.
