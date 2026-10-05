<!-- SPDX-License-Identifier: Apache-2.0 -->

# T-IB-09 evidence snapshot

This directory preserves the source statement and historical checking report used by [THEOREMS.md](../../../THEOREMS.md#t-ib-09). These are evidence snapshots under this repository's Apache-2.0 license, not a new formal-verification result.

| File | Origin | SHA-256 |
| ---- | ------ | ------- |
| [statement.lean](statement.lean) | Canonical `lean-proofs-to-prove/T-IB-09-adversarial-dissipation.lean`; identical to the saved Aristotle project's source | `b3b1b7358d955449b24b7d9a643d4d0f0ac7606ae3af577a2554a213efece365` |
| [ARISTOTLE_SUMMARY.md](ARISTOTLE_SUMMARY.md) | Saved `aristotle-outputs/corpus-theorems/T-IB-09/T-IB-09_aristotle/ARISTOTLE_SUMMARY.md` | `9257704f643d4dcffd5c1ceaf65a6467633057f6d48f28b4847a5c7ac7333fa7` |

The snapshots were copied byte-for-byte on 2026-10-05 from the local Viridis Bounty Hunter workspace. The report identifies project `f6dd4bcd-b9f2-4818-940f-c6f52fd360c0` and reports four compiled arithmetic corollaries and their standard Lean axiom dependencies. This change did not run Lean, Aristotle, or an independent kernel audit.

The source's historical header says `Aristotle status: STUB`, lists Lean v4.24.0 and a Mathlib revision, and retains an `EXPECTED ARISTOTLE OUTCOMES` footer. The saved output project's toolchain instead names Lean v4.28.0 / Mathlib v4.28.0. Those comments were preserved; their product claims are not current evidence of a physical dissipation guarantee. The checking report concerns conditional arithmetic statements whose first three bounds are explicit hypotheses. The external `asymmetric_defense_property` axiom is declared but is not invoked by those proofs according to the saved report.

Keep the source/report hashes and the public explanation together when updating these snapshots. Replacing historical evidence or asserting fresh checking requires a separately reviewed proof package.
