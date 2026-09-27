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
3. **A new class in its own registry file.** Motifs register as
   `PrimitiveClass::CircuitMotif` with `primitive_domain =
   "structural-circuit"` (ADR-0004 §5 keeps domains explicit), stored in
   `circuit_registry.json` beside the field registry, **not in it**. That
   keeps three things apart:
   - **Older binaries.** A build without the new variant cannot parse it, and
     swarm agents share the data dir, so a motif in `registry.json` would
     break every deployed archivist, explorer and `serve` process on its next
     load. `PrimitiveClass` also gains `#[serde(other)]` on `Unknown`, so from
     this build on an unknown class loads as `Unknown` instead of failing.
   - **Field-only machinery.** Novelty and duplicate checks in discovery,
     `.crystal` `MERGE`/`SPLIT`, and growth-cap pruning compare signatures as
     spatial structure; a circuit composition vector would pollute all three.
   - **Registry races.** Like any registry write, `circuit --register` and
     `--reproduce` should not run against a data dir whose swarm agents are
     live: copy it to a scratch dir first (CLAUDE.md).

   The authoritative numbers live in the optional `Primitive::circuit` field
   (`CircuitMotifMeta`: source, blake3 of the op-stream bytes, miner version,
   window, tokens, counts). Field-shaped fields get documented structural
   analogues, so the rows read like any primitive:

   | field | meaning for a Circuit Motif |
   |---|---|
   | persistence, stability_score | share of all Toffolis the motif covers |
   | centroid | (first, last) instance position as fractions of the stream |
   | area | motif length in gates |
   | energy_profile | 1.0 at each Toffoli position in the motif |
   | noise_tolerance | 0 (not applicable) |
   | signature | 256-bin L2-normalised composition (kind × target rank × first control rank), for similarity ranking only |
   | hash | blake3 of the canonical unit (below) |

   **Identity is the canonical unit**, not the signature: the smallest
   repeating block of the token sequence, in its lexicographically least
   rotation. The same cycle anchored at a different Toffoli, and a run of one
   motif at a longer window, reduce to one primitive. Motifs that differ in
   gate order or in any operand rank stay distinct. (The composition
   signature ignores order, so it must not decide identity: two reorderings
   of one gate set share it exactly.)
4. **Evidence.** Registration is Level 1 (Observed), as for field
   primitives. Level 2 is `circuit-remine-v1`: re-read the same bytes (the
   blake3 must match) and count the recorded token sequence again; a mismatch
   demotes to Level 1, and the record carries the recorded and current miner
   versions. Mining is deterministic, so on unchanged bytes this is a check
   that the claim, the stream and the miner still agree (it catches a changed
   miner, a hand-edited row, or a row attached to the wrong stream), **not** a
   statistical replication like the field procedures. The physics procedures
   and behavioral contracts re-run a material simulation, so `promote`
   refuses Circuit Motifs.
5. **Untrusted input.** The op-count header is checked against the raw body
   size before anything is allocated, the initial allocation is bounded for
   the zstd framing, and trailing bytes or extra frames are an error.

## Consequences

- Native-only (file IO); the wasm engine build is untouched apart from the
  new enum variant. One dependency: `ruzstd` (pure-Rust, decode-only).
- On the ECDSA.fail record, one 4-gate motif, `CCX(2,1>far) CX(3>1)
  CX(0>far) CX(1>far)`, covers 709,637 Toffoli (76.3%): the ripple-carry
  step, found with no access to the source. Mining the full 12.2M-op stream
  takes ~4 s in release. The decoded ops are held in memory (32 bytes each,
  ~390 MB for this stream); the 56-byte records are not.
- Not claimed: that a motif is optimal, or that rewriting it lowers the
  score. Motifs say where the cost is; changing it is the optimiser's job.
- The same canonical unit from two circuits is one primitive (first source
  wins), so `--reproduce` against the second circuit reports a source
  mismatch. Revisit if per-source rows are needed.
- Circuit Motifs don't appear in `primitives`, the Observatory or the API,
  which read `registry.json`. A listing surface for `circuit_registry.json`
  is future work.