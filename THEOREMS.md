# Theorems

Maxwell's Defense implements a SHA-256 proof-of-work gate. Its cryptographic search-cost argument is separate from the conditional thermodynamic model in the **Intelligence Bound corpus** maintained by Viridis Security.

The corpus catalog and Lean 4 sources live at [github.com/viridis-security/vulncanon](https://github.com/viridis-security/vulncanon) under `knowledge-base/frameworks/CORPUS_THEOREMS.md` and the proof queue at `lean-proofs-to-prove/`.

<a id="cryptographic-guarantees"></a>

## What this library guarantees independently of any corpus proof

- **Authenticated challenges.** [Challenge issuance and verification](python/maxwells_defense/core.py) bind the nonce, difficulty, expiry, and context with HMAC-SHA256. This relies on the standard HMAC security assumption. [Regression tests](python/tests/test_invariants.py) cover tampering, expiry, context mismatch, and insufficient work.
- **Expected search effort under a model.** For a fresh challenge and classical distinct queries, modeling SHA-256 as a random oracle gives success probability `2^-d` per query, expected search effort `2^d` queries, and success probability at most `min(1, q / 2^d)` after `q` queries. This is a probability argument under the model, not a Lean-mechanized result in this repository. It does not bound wall time, electricity use, or quantum search. [Dwork & Naor (1992)](https://www.microsoft.com/en-us/research/publication/pricing-via-processing-or-combatting-junk-mail/) introduce computational access pricing; [Bellare & Rogaway (1993)](https://www.cs.ucdavis.edu/~rogaway/papers/ro-abstract.html) describe the random-oracle modeling methodology.
- **Verification cost constant in difficulty.** [The verifier](python/maxwells_defense/core.py) computes one HMAC, one candidate SHA-256, and a leading-zero count bounded by the 32-byte digest length. This is O(1) in `d` for fixed input lengths; hashing unbounded input is not constant-time in input size.

These implementation properties do not prove a thermodynamic bound, an economic outcome, or the absence of vulnerabilities. A search-effort bound for a fresh solution alone does not establish one solve per accepted request; replay protection is a separate stateful property.

<a id="t-ib-09"></a>
<a id="t-ib-09--adversarial-dissipation-theorem"></a>

## T-IB-09 — Adversarial Dissipation Theorem (conditional research model)

**Status:** Historical Aristotle checking report, with one declared external axiom and explicit dissipation hypotheses. The [saved summary](docs/artifacts/t-ib-09/ARISTOTLE_SUMMARY.md) for project `f6dd4bcd-b9f2-4818-940f-c6f52fd360c0` reports that four arithmetic corollaries compiled with zero `sorry` terms. It also reports that none invokes the declared axiom: the dissipation bounds enter as explicit hypotheses. The [source statement](docs/artifacts/t-ib-09/statement.lean) still says `STUB` and lists expected outcomes in its historical comments. [Provenance](docs/artifacts/t-ib-09/README.md) records that discrepancy. No fresh Lean or Aristotle check was performed for this documentation change.

### Axioms and what they assume

The [source](docs/artifacts/t-ib-09/statement.lean) declares exactly one additional axiom:

```
asymmetric_defense_property (d : DefenseProfile) (E_atk : ℝ) :
    E_atk ≥ d.M * d.E_legit
```

This **assumes** the physical dissipation asymmetry; it does not derive it from SHA-256, Landauer's principle, or measured hardware. It is an external modeling assertion, not a foundational axiom such as classical choice. As written, it quantifies over arbitrary `E_atk` without a defense-validity premise, so it must not be treated as a validated physical model. The four corollaries below instead reason from explicit premises.

The PoW literature motivates requiring computational effort before access; the random-oracle argument above bounds classical hash queries. Neither cited result supplies the missing bridge from hash queries to `N · M · k_B · T · ln 2` joules for this deployment. In particular, `2^d` expected hashes per fresh solution is not a demonstrated physical amplification factor `M`, a per-bit energy measurement, or a claim that the defender operates at the Landauer floor.

### What the conditional corollaries say

The exact [Lean declarations](docs/artifacts/t-ib-09/statement.lean) and [saved checking report](docs/artifacts/t-ib-09/ARISTOTLE_SUMMARY.md) are the evidence for this table:

| Corollary | Explicit premise | Arithmetic conclusion |
| --------- | ---------------- | --------------------- |
| T-IB-09a `attacker_per_request_bound` | `E_atk ≥ M · E_legit`, `M ≥ 1`, `E_legit > 0` | `E_atk ≥ E_legit` |
| T-IB-09b `campaign_cost_asymmetric` | `E_atk_campaign ≥ n · M · E_legit`, with nonnegative `n` and profile bounds | `E_atk_campaign ≥ n · E_legit` |
| T-IB-09c `capture_cost_amplified` | `E_atk_capture ≥ N · M · kT · ln 2`, `N ≥ 0`, and profile bounds | `E_atk_capture ≥ N · kT · ln 2` |
| T-IB-09d `attack_irrational_threshold` | `M > V / (kT · ln 2)`, `kT > 0`, and profile bounds | `M · kT · ln 2 > V` |

The first three assume the amplified cost bound and derive a weaker bound. The fourth rearranges an inequality; interpreting it as an economic threshold additionally requires comparable units, a supported energy-to-value model, and deployment evidence. They do not establish the load-bearing thermodynamic claim or guaranteed unprofitability. The saved summary's reference to standard Lean axioms concerns these conditional arithmetic statements only.

**Future work:** A separate model could formalize the random-oracle query bound and explicitly justify any deployment-specific energy conversion. That work, fresh checking, and completion of T-IB-02 are outside this change.

## T-IB-02 — Adversarial Landauer Inequality (companion)

**Status:** Lean stub authored. Mechanized proof in the Aristotle queue. Expected to require splitting into 3–4 lemmas.

**Informal statement.** A defender's expected per-bit cost to detect an attribution break at false-negative rate `α` exceeds an attacker's per-bit cost to capture bits irreversibly by a factor of `log₂(1/α)`.

| Term                                  | Expression                    |
| ------------------------------------- | ----------------------------- |
| Attacker per-bit cost (Landauer min.) | `k_B · T · ln 2`              |
| Defender per-bit cost (detection)     | `k_B · T · ln 2 · log₂(1/α)`  |
| Ratio (defender:attacker)             | `log₂(1/α)`                   |

At `α = 10⁻³`, defender pays ~10× per bit. At `α = 10⁻⁶`, ~20×.

**The role T-IB-02 plays here.** Without an active defense like Maxwell, the *natural* per-bit asymmetry runs the wrong way — defenders pay more than attackers under purely statistical detection. T-IB-09 inverts that asymmetry through pre-paid attacker dissipation. T-IB-02 is the baseline; T-IB-09 is the cure.

**Lean source:** [`lean-proofs-to-prove/T-IB-02-adversarial-landauer.lean`](https://github.com/viridis-security/vulncanon/blob/main/lean-proofs-to-prove/T-IB-02-adversarial-landauer.lean). Aristotle proof pending.

## Related theorems

The Intelligence Bound corpus contains additional theorems composable with T-IB-09 that may inform future versions of this library:

| Theorem  | Title                       | Connection to Maxwell's Defense                                                            | Status |
| -------- | --------------------------- | ------------------------------------------------------------------------------------------ | ------ |
| T-IB-01  | Attribution Conservation    | Foundation for Maxwell Energy Receipts (signed cross-site proof-of-work attestations)      | STUB   |
| T-IB-04  | Composability Attribution   | Federated difficulty: attribution across pooled defender signals                           | STUB   |
| T-IB-06  | Detection Lower Bound       | Floor on detection cost — frames when PoW is the right tool vs. signature-based detection  | STUB   |
| T-IB-07  | Conservation Closure        | Ledger invariant for receipts crossing trust domains                                       | STUB   |

## Falsifiability

If you can demonstrate any of the following, the library is broken and we want an issue:

1. A solution that verifies with fewer than `d` leading zero bits on `sha256(server_nonce || solution_nonce)`.
2. A tampered challenge (any field changed) that verifies with its original HMAC signature.
3. An expired challenge that verifies with its original HMAC signature when `now > expires_at`.
4. A verification path with non-constant cost in `d` (the only loop in verify is bounded by the digest length, 32 bytes).
5. Any function or constant in the public API whose name matches `/attack|exploit|bypass|payload/`.

The first four are tested in `python/tests/test_invariants.py`. The fifth is lint-enforced in the same file.

## Citation

If you cite the implementation in academic work, keep the conditional research status explicit:

```bibtex
@misc{viridis2026maxwell,
  author       = {Hart, Justin and {Viridis Security}},
  title        = {Maxwell's Defense: SHA-256 Proof-of-Work Reference},
  year         = {2026},
  howpublished = {\url{https://github.com/viridis-security/maxwells-defense}},
  note         = {Classical search-cost argument under a random-oracle model.
                  T-IB-09 is conditional on explicit dissipation hypotheses;
                  its source declares one external asymmetry axiom.}
}
```
