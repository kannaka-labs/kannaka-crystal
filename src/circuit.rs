//! Circuit primitives (ADR-0005): recurring gate motifs mined from a
//! reversible/quantum op stream and registered as Crystal Primitives.
//!
//! The Crystal Engine looks for structures that persist in a resonant field.
//! This module looks for the same thing in a circuit: a construction that
//! recurs through the op stream. Each gate is rewritten by *recency*: every
//! operand becomes its move-to-front rank among recently used qubits, so one
//! construction reads identically on any register and at any width (plain
//! qubit offsets do not: on the ECDSA.fail record they give 189k distinct
//! tokens, recency gives 1,291). Motifs are anchored on a Toffoli and ranked
//! by how many of the stream's Toffolis they account for, which is what
//! circuit-cost metrics such as ECDSA.fail's (Toffoli count x peak qubits)
//! charge for.
//!
//! Input is the ECDSA.fail `ops.bin` framing: an 8-byte magic (`QECCOPSZ` =
//! zstd body, `QECCOPS1` = raw body), a u64 op count, then 56-byte records
//! (u32 kind, u32 pad, u64 q_control2, q_control1, q_target, c_target,
//! c_condition, r_target; all little-endian).

use crate::primitives::{Classification, DetectedStructure, MorphologyFeatures, PrimitiveClass};
use crate::registry::{EvidenceRecord, Primitive, Registry};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// Op kinds of the ECDSA.fail op stream that this module reads.
pub mod kind {
    pub const X: u32 = 6;
    pub const Z: u32 = 7;
    pub const CX: u32 = 8;
    pub const CZ: u32 = 9;
    pub const SWAP: u32 = 10;
    pub const R: u32 = 11;
    pub const HMR: u32 = 12;
    pub const CCX: u32 = 13;
    pub const CCZ: u32 = 14;
}

/// Gates kept for mining. Swaps are dropped: they are free in the cost
/// metric and their register-shift cascades would otherwise swamp every
/// motif. Bookkeeping ops (registers, conditions, classical writes) carry no
/// gate structure.
const MINED_KINDS: [u32; 8] = [
    kind::X,
    kind::Z,
    kind::CX,
    kind::CZ,
    kind::R,
    kind::HMR,
    kind::CCX,
    kind::CCZ,
];

const NO_QUBIT: u64 = u64::MAX;
const OP_BYTES: usize = 56;
/// Operand ranks at or beyond this collapse to "far" (a qubit not touched
/// recently). 48 covers a ripple-carry step's working set with room to spare.
pub const RECENCY_CAP: u32 = 48;
/// Marks an unused operand slot in a [`Token`].
pub const ABSENT: u32 = u32::MAX;
pub const MINER_VERSION: &str = "circuit-motif-v1";
pub const REMINE_PROCEDURE: &str = "circuit-remine-v1";

/// One gate as stored in the op stream (the fields mining needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Op {
    pub kind: u32,
    pub c2: u64,
    pub c1: u64,
    pub t: u64,
}

/// Decode a `QECCOPSZ` / `QECCOPS1` op stream.
pub fn parse_ops(bytes: &[u8]) -> Result<Vec<Op>, String> {
    if bytes.len() < 16 {
        return Err("op stream too short for its header".into());
    }
    let n = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")) as usize;
    match &bytes[..8] {
        b"QECCOPS1" => read_ops(&bytes[16..], n),
        b"QECCOPSZ" => {
            let dec = ruzstd::decoding::StreamingDecoder::new(&bytes[16..])
                .map_err(|e| format!("zstd: {e}"))?;
            read_ops(dec, n)
        }
        _ => Err("not a QECCOPS op stream (bad magic)".into()),
    }
}

/// Stream-decode `n` records so the uncompressed body (56 bytes per op,
/// ~685 MB for the ECDSA.fail record) is never materialised.
fn read_ops(mut r: impl Read, n: usize) -> Result<Vec<Op>, String> {
    let u64at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    let mut rec = [0u8; OP_BYTES];
    let mut ops = Vec::with_capacity(n.min(1 << 26));
    for i in 0..n {
        r.read_exact(&mut rec)
            .map_err(|e| format!("truncated at op {i} of {n}: {e}"))?;
        ops.push(Op {
            kind: u32::from_le_bytes(rec[0..4].try_into().expect("4 bytes")),
            c2: u64at(&rec, 8),
            c1: u64at(&rec, 16),
            t: u64at(&rec, 24),
        });
    }
    Ok(ops)
}

/// A recency-coded gate: its kind plus each operand's move-to-front rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    pub kind: u32,
    pub r2: u32,
    pub r1: u32,
    pub rt: u32,
}

impl Token {
    pub fn is_toffoli(&self) -> bool {
        matches!(self.kind, kind::CCX | kind::CCZ)
    }

    /// Human-readable form, e.g. `CCX(1,4>0)`: control ranks, then `>` and
    /// the target's rank; `far` is a rank at or beyond [`RECENCY_CAP`].
    pub fn spell(&self) -> String {
        let name = match self.kind {
            kind::X => "X",
            kind::Z => "Z",
            kind::CX => "CX",
            kind::CZ => "CZ",
            kind::R => "R",
            kind::HMR => "HMR",
            kind::CCX => "CCX",
            kind::CCZ => "CCZ",
            _ => "?",
        };
        let rank = |r: u32| {
            if r >= RECENCY_CAP {
                "far".to_string()
            } else {
                r.to_string()
            }
        };
        let controls: Vec<String> = [self.r2, self.r1]
            .into_iter()
            .filter(|r| *r != ABSENT)
            .map(rank)
            .collect();
        if controls.is_empty() {
            format!("{name}({})", rank(self.rt))
        } else {
            format!("{name}({}>{})", controls.join(","), rank(self.rt))
        }
    }
}

/// A recency-coded stream: token ids into `table`.
#[derive(Debug, Clone)]
pub struct Tokenized {
    pub tokens: Vec<u32>,
    pub table: Vec<Token>,
    pub toffolis: usize,
}

/// Rewrite gates by recency. Operands are looked up in the order control2,
/// control1, target, and each lookup moves its qubit to the front, so a
/// construction's internal reuse pattern is captured exactly.
pub fn recency_tokens(ops: &[Op]) -> Tokenized {
    let mut recent: Vec<u64> = Vec::with_capacity(RECENCY_CAP as usize + 1);
    let mut ids: HashMap<Token, u32> = HashMap::new();
    let mut table = Vec::new();
    let mut tokens = Vec::new();
    let mut toffolis = 0;
    for op in ops.iter().filter(|o| MINED_KINDS.contains(&o.kind)) {
        let mut rank = |q: u64| -> u32 {
            if q == NO_QUBIT {
                return ABSENT;
            }
            let r = match recent.iter().position(|x| *x == q) {
                Some(i) => {
                    recent.remove(i);
                    i as u32
                }
                None => RECENCY_CAP,
            };
            recent.insert(0, q);
            recent.truncate(RECENCY_CAP as usize);
            r
        };
        let tok = Token {
            kind: op.kind,
            r2: rank(op.c2),
            r1: rank(op.c1),
            rt: rank(op.t),
        };
        if tok.is_toffoli() {
            toffolis += 1;
        }
        let id = *ids.entry(tok).or_insert_with(|| {
            table.push(tok);
            (table.len() - 1) as u32
        });
        tokens.push(id);
    }
    Tokenized {
        tokens,
        table,
        toffolis,
    }
}

/// A recurring motif: `window` consecutive recency-coded gates starting at
/// a Toffoli.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Motif {
    pub window: usize,
    pub tokens: Vec<Token>,
    /// Non-overlapping instances (greedy, left to right).
    pub occurrences: usize,
    pub toffoli_per_instance: usize,
    /// `occurrences * toffoli_per_instance`: the Toffolis this motif accounts for.
    pub toffoli_covered: usize,
    pub first_position: usize,
    pub last_position: usize,
}

impl Motif {
    pub fn spelled(&self) -> Vec<String> {
        self.tokens.iter().map(Token::spell).collect()
    }
}

/// Mine the `top` motifs of length `window`, ranked by Toffolis covered.
/// Windows are grouped by exact token content (no hashing shortcuts), so
/// counts are exact.
pub fn mine(tk: &Tokenized, window: usize, top: usize) -> Vec<Motif> {
    if window == 0 || tk.tokens.len() < window {
        return Vec::new();
    }
    let mut groups: HashMap<&[u32], Vec<usize>> = HashMap::new();
    for p in 0..=tk.tokens.len() - window {
        if tk.table[tk.tokens[p] as usize].is_toffoli() {
            groups.entry(&tk.tokens[p..p + window]).or_default().push(p);
        }
    }
    let mut motifs: Vec<Motif> = groups
        .into_iter()
        .map(|(ids, positions)| {
            let mut occurrences = 0;
            let mut next_free = 0;
            for &p in &positions {
                if p >= next_free {
                    occurrences += 1;
                    next_free = p + window;
                }
            }
            let tokens: Vec<Token> = ids.iter().map(|i| tk.table[*i as usize]).collect();
            let per = tokens.iter().filter(|t| t.is_toffoli()).count();
            Motif {
                window,
                occurrences,
                toffoli_per_instance: per,
                toffoli_covered: occurrences * per,
                first_position: positions[0],
                last_position: *positions.last().expect("non-empty group"),
                tokens,
            }
        })
        .collect();
    // Deterministic order: coverage, then earliest appearance.
    motifs.sort_by(|a, b| {
        b.toffoli_covered
            .cmp(&a.toffoli_covered)
            .then(a.first_position.cmp(&b.first_position))
    });
    motifs.truncate(top);
    motifs
}

/// Circuit-specific metadata carried on a registered Circuit Motif.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMotifMeta {
    pub miner_version: String,
    /// Where the stream came from, e.g. `ecdsafail@5a08ebd`.
    pub source: String,
    /// blake3 of the op-stream file: re-mining must see the same bytes.
    pub source_hash: String,
    pub gates_total: usize,
    pub toffoli_total: usize,
    pub window: usize,
    pub tokens: Vec<Token>,
    pub spelled: Vec<String>,
    pub occurrences: usize,
    pub toffoli_per_instance: usize,
    pub toffoli_covered: usize,
}

const KIND_BINS: [u32; 8] = MINED_KINDS;

/// 256-bin L2-normalised composition signature (kind x target rank x first
/// control rank), comparable with [`crate::primitives::signature_similarity`].
/// It is rotation-invariant by construction, so the same cycle anchored at
/// a different Toffoli deduplicates to one primitive.
pub fn signature(tokens: &[Token]) -> Vec<f64> {
    let mut sig = vec![0.0; 256];
    for t in tokens {
        let k = KIND_BINS.iter().position(|x| *x == t.kind).unwrap_or(0);
        let rt = t.rt.min(7) as usize;
        let r1 = if t.r1 == ABSENT {
            0
        } else {
            t.r1.min(3) as usize
        };
        sig[k * 32 + rt * 4 + r1] += 1.0;
    }
    let norm = sig.iter().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 0.0 {
        sig.iter_mut().for_each(|v| *v /= norm);
    }
    sig
}

/// Register a motif. Returns `None` if the registry already holds a Circuit
/// Motif with the same composition (similarity >= 0.92).
///
/// Field-shaped [`Primitive`] fields are filled with structural analogues,
/// documented in ADR-0005: persistence and stability = share of all
/// Toffolis covered; centroid = (first, last) position as fractions of the
/// stream; area = window; energy_profile = 1.0 at each Toffoli in the motif;
/// noise_tolerance = 0 (not applicable). The authoritative numbers live in
/// [`Primitive::circuit`].
pub fn register_motif(
    registry: &mut Registry,
    tk: &Tokenized,
    motif: &Motif,
    source: &str,
    source_hash: &str,
) -> Option<Primitive> {
    let len = tk.tokens.len().max(1) as f64;
    let share = motif.toffoli_covered as f64 / tk.toffolis.max(1) as f64;
    let distinct = {
        let mut v = motif.tokens.clone();
        v.sort_by_key(|t| (t.kind, t.r2, t.r1, t.rt));
        v.dedup();
        v.len()
    };
    let detected = DetectedStructure {
        class: PrimitiveClass::CircuitMotif,
        classification: Classification {
            display_class: PrimitiveClass::CircuitMotif.to_string(),
            primitive_domain: "structural-circuit".into(),
            classifier_version: MINER_VERSION.into(),
            // Exact counting, not a heuristic.
            classifier_confidence: 1.0,
            features: MorphologyFeatures {
                relative_area: share,
                elongation: motif.window as f64,
                annularity: 0.0,
                angular_gap_count: motif.toffoli_per_instance,
                occupied_bins: distinct,
                stability_ratio: motif.occurrences as f64,
            },
        },
        centroid: (
            motif.first_position as f64 / len,
            motif.last_position as f64 / len,
        ),
        area: motif.window,
        stability_score: share,
        signature: signature(&motif.tokens),
    };
    let energy: Vec<f64> = motif
        .tokens
        .iter()
        .map(|t| if t.is_toffoli() { 1.0 } else { 0.0 })
        .collect();
    let prim = registry.register(
        &detected,
        share,
        0.0,
        energy,
        &format!("circuit:{source}"),
        vec![],
        &format!("{MINER_VERSION} window {} from {source}", motif.window),
        None,
        None,
    )?;
    let meta = CircuitMotifMeta {
        miner_version: MINER_VERSION.into(),
        source: source.into(),
        source_hash: source_hash.into(),
        gates_total: tk.tokens.len(),
        toffoli_total: tk.toffolis,
        window: motif.window,
        tokens: motif.tokens.clone(),
        spelled: motif.spelled(),
        occurrences: motif.occurrences,
        toffoli_per_instance: motif.toffoli_per_instance,
        toffoli_covered: motif.toffoli_covered,
    };
    let stored = registry.find_mut(&prim.id).expect("just registered");
    stored.circuit = Some(meta);
    Some(stored.clone())
}

/// Circuit motifs are not field structures: the physics evidence procedures
/// and behavioral contracts (which re-run a material simulation) do not
/// apply to them. Their Level 2 is [`remine`].
pub fn ensure_field_primitive(p: &Primitive) -> Result<(), String> {
    if p.class == PrimitiveClass::CircuitMotif {
        return Err(format!(
            "{} is a Circuit Motif: field procedures don't apply; \
             use `kannaka-crystal circuit <ops.bin> --reproduce {}`",
            p.id, p.id
        ));
    }
    Ok(())
}

/// Level 2 for circuit motifs: re-mine the same source bytes and require the
/// motif to reappear with identical counts. A mismatch demotes to Level 1.
pub fn remine(
    registry: &mut Registry,
    id: &str,
    tk: &Tokenized,
    source_hash: &str,
) -> Result<EvidenceRecord, String> {
    let prim = registry
        .find(id)
        .ok_or_else(|| format!("unknown primitive: {id}"))?;
    let meta = prim
        .circuit
        .clone()
        .ok_or_else(|| format!("{id} is not a Circuit Motif"))?;
    if meta.source_hash != source_hash {
        return Err(format!(
            "source mismatch: {id} was mined from {} (blake3 {}), this file hashes to {source_hash}",
            meta.source, meta.source_hash
        ));
    }
    let found = mine(tk, meta.window, usize::MAX)
        .into_iter()
        .find(|m| m.tokens == meta.tokens);
    let (occ, covered) = found
        .as_ref()
        .map(|m| (m.occurrences, m.toffoli_covered))
        .unwrap_or((0, 0));
    let success = occ == meta.occurrences && covered == meta.toffoli_covered;
    let record = EvidenceRecord {
        level: 2,
        procedure: REMINE_PROCEDURE.into(),
        metrics: serde_json::json!({
            "success": success,
            "occurrences": occ,
            "expected_occurrences": meta.occurrences,
            "toffoli_covered": covered,
            "expected_toffoli_covered": meta.toffoli_covered,
            "source_hash": source_hash,
        }),
        at: Utc::now(),
        node: std::env::var("KANNAKA_CRYSTAL_NODE").unwrap_or_else(|_| "local".into()),
    };
    let stored = registry.find_mut(id).expect("found above");
    if success {
        stored.evidence_level = stored.evidence_level.max(2);
    } else {
        stored.evidence_level = stored.evidence_level.min(1);
    }
    stored.evidence_records.push(record.clone());
    Ok(record)
}

/// Read, decode and recency-code an op-stream file. Returns the tokenized
/// stream and the blake3 of the file bytes.
pub fn load_tokenized(path: &Path) -> Result<(Tokenized, String), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let ops = parse_ops(&bytes)?;
    Ok((recency_tokens(&ops), hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(kind: u32, c2: u64, c1: u64, t: u64) -> Op {
        Op { kind, c2, c1, t }
    }

    /// One ripple-carry-like step on qubits (a, b, c): the same construction
    /// the miner must recognise wherever it is placed.
    fn step(a: u64, b: u64, c: u64) -> Vec<Op> {
        vec![
            op(kind::CCX, a, b, c),
            op(kind::CX, NO_QUBIT, a, b),
            op(kind::HMR, NO_QUBIT, NO_QUBIT, c),
            op(kind::CZ, NO_QUBIT, a, b),
        ]
    }

    fn encode(ops: &[Op]) -> Vec<u8> {
        let mut out = b"QECCOPS1".to_vec();
        out.extend((ops.len() as u64).to_le_bytes());
        for o in ops {
            let mut rec = [0u8; OP_BYTES];
            rec[0..4].copy_from_slice(&o.kind.to_le_bytes());
            rec[8..16].copy_from_slice(&o.c2.to_le_bytes());
            rec[16..24].copy_from_slice(&o.c1.to_le_bytes());
            rec[24..32].copy_from_slice(&o.t.to_le_bytes());
            rec[32..56].copy_from_slice(&[0xff; 24]);
            out.extend(rec);
        }
        out
    }

    #[test]
    fn raw_stream_round_trips_and_bad_magic_is_rejected() {
        let ops = step(1, 2, 3);
        assert_eq!(parse_ops(&encode(&ops)).unwrap(), ops);
        let mut bad = encode(&ops);
        bad[7] = b'9';
        assert!(parse_ops(&bad).is_err());
        let truncated = &encode(&ops)[..16 + OP_BYTES];
        assert!(parse_ops(truncated).is_err());
    }

    #[test]
    fn recency_coding_is_register_independent() {
        // Warm both runs up the same way, then place the step far apart.
        let mut near = step(1, 2, 3);
        near.extend(step(1, 2, 3));
        let mut far = step(1001, 5002, 90003);
        far.extend(step(1001, 5002, 90003));
        let a = recency_tokens(&near);
        let b = recency_tokens(&far);
        let spell = |t: &Tokenized| -> Vec<String> {
            t.tokens
                .iter()
                .map(|i| t.table[*i as usize].spell())
                .collect()
        };
        assert_eq!(spell(&a), spell(&b));
        // The second instance reuses the first one's qubits, so every rank is
        // near, not `far`: the coding captures reuse rather than addresses.
        assert!(!a.table[a.tokens[4] as usize].spell().contains("far"));
        assert!(a.table[a.tokens[0] as usize].spell().contains("far"));
    }

    #[test]
    fn mining_finds_a_planted_motif_with_exact_counts() {
        let mut ops = Vec::new();
        for i in 0..50u64 {
            let base = 10 * i;
            ops.extend(step(base, base + 1, base + 2));
            // Unrelated filler that must not disturb the count.
            ops.push(op(kind::X, NO_QUBIT, NO_QUBIT, 7_000 + i));
            ops.push(op(kind::SWAP, NO_QUBIT, 7_000 + i, 8_000 + i));
        }
        let tk = recency_tokens(&ops);
        assert_eq!(tk.toffolis, 50);
        let top = mine(&tk, 4, 3);
        // Every instance lands on fresh qubits, so all 50 code identically.
        assert_eq!(top[0].occurrences, 50);
        assert_eq!(top[0].toffoli_per_instance, 1);
        assert_eq!(top[0].toffoli_covered, 50);
        assert!(top[0].tokens[0].is_toffoli());
    }

    #[test]
    fn registration_dedupes_rotations_and_remine_promotes() {
        let mut ops = Vec::new();
        for i in 0..20u64 {
            ops.extend(step(3 * i, 3 * i + 1, 3 * i + 2));
        }
        let tk = recency_tokens(&ops);
        let motifs = mine(&tk, 4, 2);
        let mut reg = Registry::default();
        let p = register_motif(&mut reg, &tk, &motifs[0], "unit", "h0").expect("new");
        assert_eq!(p.class, PrimitiveClass::CircuitMotif);
        let meta = p.circuit.clone().expect("meta");
        assert_eq!(meta.occurrences, motifs[0].occurrences);
        // Registering the same motif again is a duplicate.
        assert!(register_motif(&mut reg, &tk, &motifs[0], "unit", "h0").is_none());
        // Field procedures refuse it; re-mining the same bytes promotes it.
        assert!(ensure_field_primitive(&p).is_err());
        let rec = remine(&mut reg, &p.id, &tk, "h0").unwrap();
        assert_eq!(rec.metrics["success"], true);
        assert_eq!(reg.find(&p.id).unwrap().evidence_level, 2);
        // A different source is refused outright.
        assert!(remine(&mut reg, &p.id, &tk, "other").is_err());
    }

    #[test]
    fn remine_demotes_when_counts_change() {
        let mut ops = Vec::new();
        for i in 0..20u64 {
            ops.extend(step(3 * i, 3 * i + 1, 3 * i + 2));
        }
        let tk = recency_tokens(&ops);
        let motif = mine(&tk, 4, 1).remove(0);
        let mut reg = Registry::default();
        let p = register_motif(&mut reg, &tk, &motif, "unit", "h0").unwrap();
        reg.find_mut(&p.id).unwrap().evidence_level = 2;
        // Same hash, fewer instances: the stored claim no longer reproduces.
        let fewer = recency_tokens(&ops[..40]);
        let rec = remine(&mut reg, &p.id, &fewer, "h0").unwrap();
        assert_eq!(rec.metrics["success"], false);
        assert_eq!(reg.find(&p.id).unwrap().evidence_level, 1);
    }
}
