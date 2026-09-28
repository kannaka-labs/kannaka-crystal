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

use crate::primitives::{Classification, MorphologyFeatures, PrimitiveClass};
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
    let n = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
    match &bytes[..8] {
        b"QECCOPS1" => {
            // The raw body's size bounds the op count exactly: never trust the header beyond it.
            let body = (bytes.len() - 16) as u64;
            if n > body / OP_BYTES as u64 {
                return Err(format!(
                    "header claims {n} ops but the body holds {}",
                    body / OP_BYTES as u64
                ));
            }
            if body != n * OP_BYTES as u64 {
                return Err(format!(
                    "{} trailing bytes after {n} ops",
                    body - n * OP_BYTES as u64
                ));
            }
            read_ops(&bytes[16..], n as usize)
        }
        b"QECCOPSZ" => {
            let mut dec = ruzstd::decoding::StreamingDecoder::new(&bytes[16..])
                .map_err(|e| format!("zstd: {e}"))?;
            let ops = read_ops(
                &mut dec,
                usize::try_from(n).map_err(|_| "op count overflows usize")?,
            )?;
            let mut extra = [0u8; 1];
            if dec.read(&mut extra).map_err(|e| format!("zstd: {e}"))? != 0 {
                return Err(format!("trailing data after {n} ops"));
            }
            Ok(ops)
        }
        _ => Err("not a QECCOPS op stream (bad magic)".into()),
    }
}

/// Decode `n` records one at a time, so the uncompressed body (56 bytes per
/// op, ~685 MB for the ECDSA.fail record) is never held in memory; only the
/// 32-byte `Op` values are kept. The initial allocation is bounded, so a
/// hostile header cannot reserve memory before any data has been read.
fn read_ops(mut r: impl Read, n: usize) -> Result<Vec<Op>, String> {
    let u64at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    let mut rec = [0u8; OP_BYTES];
    let mut ops = Vec::with_capacity(n.min(1 << 16));
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

/// (Toffolis covered, first position, last position, occurrences, token ids,
/// Toffolis per instance): one ranked window group before it becomes a Motif.
type Ranked<'a> = (usize, usize, usize, usize, &'a [u32], usize);

/// Mine the `top` motifs of length `window`, ranked by Toffolis covered.
/// Windows are grouped by exact token content (no hashing shortcuts), so
/// counts are exact. Groups are ranked on lightweight tuples first and only
/// the top ones are turned into [`Motif`]s, so memory stays proportional to
/// the number of distinct windows, not to `top`.
pub fn mine(tk: &Tokenized, window: usize, top: usize) -> Vec<Motif> {
    if window == 0 || tk.tokens.len() < window {
        return Vec::new();
    }
    // positions are pushed in increasing order, which the greedy count relies on
    let mut groups: HashMap<&[u32], Vec<usize>> = HashMap::new();
    for p in 0..=tk.tokens.len() - window {
        if tk.table[tk.tokens[p] as usize].is_toffoli() {
            groups.entry(&tk.tokens[p..p + window]).or_default().push(p);
        }
    }
    let mut ranked: Vec<Ranked> = groups
        .into_iter()
        .map(|(ids, positions)| {
            let occurrences = greedy_count(&positions, window);
            let per = ids
                .iter()
                .filter(|i| tk.table[**i as usize].is_toffoli())
                .count();
            let last = *positions.last().expect("non-empty group");
            (occurrences * per, positions[0], last, occurrences, ids, per)
        })
        .collect();
    // Deterministic order: coverage, then earliest appearance.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked.truncate(top);
    ranked
        .into_iter()
        .map(|(covered, first, last, occurrences, ids, per)| Motif {
            window,
            tokens: ids.iter().map(|i| tk.table[*i as usize]).collect(),
            occurrences,
            toffoli_per_instance: per,
            toffoli_covered: covered,
            first_position: first,
            last_position: last,
        })
        .collect()
}

/// Non-overlapping instances among sorted start positions, left to right.
fn greedy_count(positions: &[usize], window: usize) -> usize {
    let (mut n, mut next_free) = (0, 0);
    for &p in positions {
        if p >= next_free {
            n += 1;
            next_free = p + window;
        }
    }
    n
}

/// Count one given token sequence directly (used by [`remine`]): no full mine.
/// Returns (occurrences, Toffolis covered).
pub fn count_motif(tk: &Tokenized, tokens: &[Token]) -> (usize, usize) {
    let ids: Option<Vec<u32>> = tokens
        .iter()
        .map(|t| tk.table.iter().position(|x| x == t).map(|i| i as u32))
        .collect();
    let Some(ids) = ids else { return (0, 0) };
    let w = ids.len();
    if w == 0 || tk.tokens.len() < w {
        return (0, 0);
    }
    let positions: Vec<usize> = (0..=tk.tokens.len() - w)
        .filter(|&p| tk.tokens[p..p + w] == ids[..])
        .collect();
    let occ = greedy_count(&positions, w);
    (occ, occ * tokens.iter().filter(|t| t.is_toffoli()).count())
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
/// It ignores gate ORDER, so it is used only to rank similar motifs, never to
/// decide identity: that is [`canonical_unit`].
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

/// Identity of a motif: its smallest repeating block, in its lexicographically
/// least rotation. A run of one motif at a longer window, or the same cycle
/// anchored at a different Toffoli, reduces to the same unit; motifs that
/// differ in gate order or in any operand rank do not.
pub fn canonical_unit(tokens: &[Token]) -> Vec<Token> {
    let n = tokens.len();
    let key = |t: &Token| (t.kind, t.r2, t.r1, t.rt);
    let p = (1..=n)
        .find(|&p| n.is_multiple_of(p) && (p..n).all(|i| tokens[i] == tokens[i - p]))
        .unwrap_or(n);
    let unit = &tokens[..p];
    (0..p)
        .map(|r| {
            unit[r..]
                .iter()
                .chain(&unit[..r])
                .copied()
                .collect::<Vec<_>>()
        })
        .min_by(|a, b| a.iter().map(key).cmp(b.iter().map(key)))
        .unwrap_or_default()
}

/// Circuit Motifs live in their own file beside the field registry
/// (ADR-0005): older binaries, field discovery, the `.crystal` language and
/// registry pruning never see them.
pub fn circuit_registry_path() -> std::path::PathBuf {
    crate::registry::data_dir().join("circuit_registry.json")
}

pub fn load_circuit_registry() -> Result<Registry, String> {
    let path = circuit_registry_path();
    if !path.exists() {
        return Ok(Registry::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn save_circuit_registry(reg: &Registry) -> Result<(), String> {
    let path = circuit_registry_path();
    let dir = path.parent().expect("data dir");
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join("circuit_registry.json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(reg).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

/// Register a motif. Returns `None` if the registry already holds a Circuit
/// Motif with the same [`canonical_unit`].
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
    let unit = canonical_unit(&motif.tokens);
    let duplicate = registry.primitives.iter().any(|p| {
        p.circuit
            .as_ref()
            .is_some_and(|m| canonical_unit(&m.tokens) == unit)
    });
    if duplicate {
        return None;
    }
    let len = tk.tokens.len().max(1) as f64;
    let share = motif.toffoli_covered as f64 / tk.toffolis.max(1) as f64;
    let distinct = {
        let mut v = motif.tokens.clone();
        v.sort_by_key(|t| (t.kind, t.r2, t.r1, t.rt));
        v.dedup();
        v.len()
    };
    let unit_bytes = serde_json::to_vec(&unit).expect("tokens serialize");
    registry.next_serial += 1;
    let prim = Primitive {
        id: format!("CRY-{:06}", registry.next_serial),
        uuid: uuid::Uuid::new_v4(),
        hash: blake3::hash(&unit_bytes).to_hex().to_string(),
        class: PrimitiveClass::CircuitMotif,
        persistence: share,
        noise_tolerance: 0.0,
        stability_score: share,
        energy_profile: motif
            .tokens
            .iter()
            .map(|t| if t.is_toffoli() { 1.0 } else { 0.0 })
            .collect(),
        material_id: format!("circuit:{source}"),
        centroid: (
            motif.first_position as f64 / len,
            motif.last_position as f64 / len,
        ),
        area: motif.window,
        signature: signature(&motif.tokens),
        lineage: vec![],
        discovered_at: Utc::now(),
        provenance: format!("{MINER_VERSION} window {} from {source}", motif.window),
        experiment_id: None,
        experiment_hash: None,
        classification: Some(Classification {
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
        }),
        evidence_level: 1,
        evidence_records: vec![],
        genome_id: None,
        parent_genome_ids: vec![],
        behavioral_capabilities: vec![],
        circuit: Some(CircuitMotifMeta {
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
        }),
    };
    registry.primitives.push(prim.clone());
    Some(prim)
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

/// Level 2 for circuit motifs: an independent re-run of the recorded procedure
/// on the same source bytes must reproduce the recorded counts. Mining is
/// deterministic, so on unchanged bytes this is a check that the claim and the
/// miner still agree (it catches a changed miner, a hand-edited row, or a row
/// attached to the wrong stream), not a statistical replication. A mismatch
/// demotes to Level 1, and the record says whether the miner version changed.
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
    let (occ, covered) = count_motif(tk, &meta.tokens);
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
            "miner_version_recorded": meta.miner_version,
            "miner_version_now": MINER_VERSION,
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
    fn hostile_header_and_trailing_bytes_are_rejected_without_allocating() {
        // 16 bytes claiming u64::MAX ops: must fail fast, not reserve memory.
        let mut hostile = b"QECCOPS1".to_vec();
        hostile.extend(u64::MAX.to_le_bytes());
        assert!(parse_ops(&hostile).unwrap_err().contains("header claims"));
        let mut extra = encode(&step(1, 2, 3));
        extra.push(0);
        assert!(parse_ops(&extra).unwrap_err().contains("trailing"));
    }

    #[test]
    fn identity_is_the_repeating_unit_not_the_composition() {
        let t = |kind, r1, rt| Token {
            kind,
            r2: ABSENT,
            r1,
            rt,
        };
        let a = t(kind::CCX, 1, RECENCY_CAP);
        let b = t(kind::CX, 3, 1);
        let c = t(kind::CX, 0, RECENCY_CAP);
        // same gates, different order: same composition signature, different motif
        assert_eq!(signature(&[a, b, c]), signature(&[a, c, b]));
        assert_ne!(canonical_unit(&[a, b, c]), canonical_unit(&[a, c, b]));
        // a rotation, and a run of the same unit, are the same motif
        assert_eq!(canonical_unit(&[a, b, c]), canonical_unit(&[b, c, a]));
        assert_eq!(
            canonical_unit(&[a, b, c, a, b, c]),
            canonical_unit(&[a, b, c])
        );
    }

    #[test]
    fn a_registry_with_an_unknown_class_still_loads() {
        let v: PrimitiveClass = serde_json::from_str("\"SomeFutureClass\"").unwrap();
        assert_eq!(v, PrimitiveClass::Unknown);
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
    fn registration_dedupes_the_same_unit_and_remine_promotes() {
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
