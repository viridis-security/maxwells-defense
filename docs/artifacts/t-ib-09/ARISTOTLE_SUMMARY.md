# Summary of changes for run f6dd4bcd-b9f2-4818-940f-c6f52fd360c0
All four theorems in `T-IB-09-adversarial-dissipation.lean` now compile and prove successfully with zero sorries and no warnings:

1. **`attacker_per_request_bound`** (T-IB-09a): Proved via `nlinarith` using `d.hM` (M ≥ 1) and `d.hELegit` (E_legit > 0).

2. **`campaign_cost_asymmetric`** (T-IB-09b): Proved by establishing `n * (M - 1) * E_legit ≥ 0` (product of non-negatives) and then using `nlinarith` to close.

3. **`capture_cost_amplified`** (T-IB-09c): Proved similarly by establishing `N * (M - 1) * kT * log 2 ≥ 0` and using `nlinarith`.

4. **`attack_irrational_threshold`** (T-IB-09d): Proved by rewriting `M * kT * log 2` as `M * (kT * log 2)` via `ring`, then applying `div_lt_iff₀` to convert the division hypothesis.

**Axiom check**: All four theorems depend only on the standard axioms (`propext`, `Classical.choice`, `Quot.sound`). None depend on the `asymmetric_defense_property` axiom — the theorems take the asymmetric-defense hypothesis as an explicit parameter rather than invoking the axiom.

**Note on the original proofs**: The original proof attempts had issues with `nlinarith` failing on nonlinear products (it needs help with terms like `n * M * E_legit` when `M ≥ 1`) and a type mismatch due to associativity (`M * kT * log 2` vs `M * (kT * log 2)`). The fixes provide the necessary intermediate non-negativity witnesses to guide `nlinarith`.