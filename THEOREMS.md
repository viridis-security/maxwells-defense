# Theorems

Maxwell's Defense is the operational implementation of theorems in the **Intelligence Bound corpus** maintained by Viridis Security. The corpus formalizes thermodynamic property rights over intelligence: attribution between dissipation and beneficiary.

The corpus catalog and Lean 4 sources live at [github.com/viridis-security/vulncanon](https://github.com/viridis-security/vulncanon) under `knowledge-base/frameworks/CORPUS_THEOREMS.md` and the proof queue at `lean-proofs-to-prove/`.

## T-IB-09 — Adversarial Dissipation Theorem (primary backing)

**Status:** ✅ Aristotle-verified 2026-05-10. Project `f6dd4bcd-b9f2-4818-940f-c6f52fd360c0`. 4/4 theorems mechanically proved under standard axioms.

**Informal statement.** An adversary capturing `N` bits of protected information under a Maxwell defense with amplification factor `M ≥ 1` dissipates at least

```
E_attacker  ≥  N · M · k_B · T · ln 2     joules
```

against the unprotected Landauer baseline of `N · k_B · T · ln 2`. The defender's per-bit cost remains at the Landauer floor.

**Why this matters operationally.** The amplification factor `M` is exactly the configurable knob Maxwell's Defense exposes (difficulty `d` in the SHA-256 reference; Argon2id memory/time parameters in the production hosted service). Setting `M = 2^d` for SHA-256 hashcash gives the literal asymmetry: attacker pays `2^d` expected hashes per protected bit, defender pays 1.

**Corollary T-IB-09d (Attack-Irrationality Threshold).** An attack is energetically irrational when

```
M · k_B · T · ln 2  >  V_per_bit
```

where `V_per_bit` is the attacker's per-bit valuation of the protected resource. For a given `V`, the defender can choose `M` to make the attack provably unprofitable in expectation.

This is the formal statement of the cocktail-napkin claim: *at sufficient PoW difficulty, the energy bill exceeds the attacker's expected payoff and the rational attacker walks away.*

**Lean source:** [`lean-proofs-to-prove/T-IB-09-adversarial-dissipation.lean`](https://github.com/viridis-security/vulncanon/blob/main/lean-proofs-to-prove/T-IB-09-adversarial-dissipation.lean). Mechanized proof artifact at Aristotle project `f6dd4bcd-b9f2-4818-940f-c6f52fd360c0`.

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

## What this library guarantees independently of any corpus proof

- The HMAC-bound challenge construction (`MX-INV-3`) is standard authenticated-public-data, secure under the standard HMAC assumption.
- The PoW lower bound is the standard Hashcash construction: SHA-256 is modeled as a random oracle for purposes of finding leading-zero-bit preimages. `2^d` expected work for `d` bits.
- Verification cost is constant by inspection of `verify_solution` (one HMAC verify, one SHA-256, one 32-byte digit count).

The corpus theorems are what make the *strategic* claim ("attack becomes thermodynamically irrational at the right `M`"); the standard cryptographic argument is what makes the *implementation* claim ("verification is O(1); attack is O(2^d)").

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

If you cite the asymmetry in academic work:

```bibtex
@misc{viridis2026maxwell,
  author       = {Hart, Justin and {Viridis Security}},
  title        = {Maxwell's Defense: Operational Implementation of the
                  Adversarial Dissipation Theorem},
  year         = {2026},
  howpublished = {\url{https://github.com/viridis-security/maxwells-defense}},
  note         = {Reference implementation of T-IB-09 in the Intelligence Bound corpus.
                  Mechanized Aristotle proof: project f6dd4bcd-b9f2-4818-940f-c6f52fd360c0.}
}
```
