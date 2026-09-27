# ADR-0005: Circuit Motifs — Structural Primitives Mined from Quantum Circuits

- **Status:** Proposed (2026-09-27)
- **Date:** 2026-09-27
- **Decision Owners:** Kannaka Crystal maintainers
- **Applies To:** Crystal Registry, CLI (`kannaka-crystal circuit`), evidence ladder
- **Related:** ADR-0004 Evidence Tiers (§5 classification domains, §9 evidence ladder)

## Context

Crystal's question is "what structure persists?", asked of a resonant field.
The same question applies to a large quantum circuit: which construction
recurs, and how much of the cost does it carry? The Yukon ECDSA.fail record
(secp256k1 point addition, 12.2M ops, 929,708 Toffoli) is the motivating
case: its cost metric is Toffoli count × peak qubits, so knowing which
construction carries the Toffolis is the first question any optimiser asks.

Plain qubit offsets do not expose that structure. The same construction runs
on different registers at shrinking widths, so offset-coded gates give 189k
distinct tokens and compress only 12x.

## Decision

1. **Recency coding.** Each gate becomes (kind, move-to-front rank of each
   operand among recently used qubits, capped at 48 = "far"). A construction
   then reads identically on any register and at any width. On the ECDSA.fail
   record: 1,291 distinct tokens and ~543x compression. Swaps are dropped:
   free in the metric, and their register-shift cascades swamp every motif.
2. **Toffoli-anchored motifs, exact counts.** Windows of `n` recency tokens
   that start at a Toffoli are grouped by exact content (no hash shortcuts);
   instances are counted non-overlapping, left to right; motifs are ranked by
   Toffolis covered (`occurrences × Toffoli per instance`).
3. **A new class, not a new registry.** Motifs register as
   `PrimitiveClass::CircuitMotif` with `primitive_domain =
   "structural-circuit"` (ADR-0004 §5 keeps domains explicit). The
   authoritative numbers live in the new optional `Primitive::circuit` field
   (`CircuitMotifMeta`: source, blake3 of the op-stream bytes, window, tokens,
   counts). Field-shaped fields get documented structural analogues so
   existing listing, search and pruning keep working:

   | field | meaning for a Circuit Motif |
   |---|---|
   | persistence, stability_score | share of all Toffolis the motif covers |
   | centroid | (first, last) instance position as fractions of the stream |
   | area | motif length in gates |
   | energy_profile | 1.0 at each Toffoli position in the motif |
   | noise_tolerance | 0 (not applicable) |
   | signature | 256-bin L2-normalised composition (kind × target rank × first control rank) |

   The composition signature is rotation-invariant, so the same cycle
   anchored at a different Toffoli deduplicates under the existing
   same-class ≥0.92 rule. So do runs of one motif at longer windows.
4. **Evidence.** Registration is Level 1 (Observed), as for field
   primitives. Level 2 is `circuit-remine-v1`: re-read the same bytes
   (blake3 must match), re-mine, and require identical counts; a mismatch
   demotes to Level 1. The physics procedures and behavioral contracts
   re-run a material simulation, so `promote` refuses Circuit Motifs.

## Consequences

- Native-only (file IO); the wasm engine build is untouched apart from the
  new enum variant. One dependency: `ruzstd` (pure-Rust, decode-only).
- On the ECDSA.fail record, one 4-gate motif, `CCX(2,1>far) CX(3>1)
  CX(0>far) CX(1>far)`, covers 709,637 Toffoli (76.3%): the ripple-carry
  step, found with no access to the source. Mining the full 12.2M-op stream
  takes ~4 s in release.
- Not claimed: that a motif is optimal, or that rewriting it lowers the
  score. Motifs say where the cost is; changing it is the optimiser's job.
- Registry dedupe is by composition across sources, so the same motif from
  two circuits is one primitive (first source wins). Revisit if per-source
  rows are needed.
