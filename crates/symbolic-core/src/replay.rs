//! Deterministic replay hash-chain (containment level L5).
//!
//! Event envelope (JSONL, canonical serialization):
//! ```json
//! {"event":{"kind":"...","payload":{...},"seq":N,"ts_ms":T},
//!  "event_hash":"<sha256 hex of canonical event>",
//!  "line_hash":"<sha256 hex of prev_hash_ascii || event_hash_ascii>",
//!  "prev_hash":"<hex>",
//!  "seq":N}
//! ```
//! Genesis `prev_hash` is 64 ASCII '0' characters.
//! The Python reference worker implements the identical scheme; shared
//! vectors live in tests/vectors/replay_chain.jsonl.

use crate::error::{FlickerError, FlickerResult};
use crate::json::{parse_json, Json};
use crate::sha2::sha256_hex;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct ReplayRecord {
    pub seq: u64,
    pub prev_hash: String,
    pub event_hash: String,
    pub line_hash: String,
    pub line: String,
}

#[derive(Debug, Default)]
pub struct ReplayWriter {
    seq: u64,
    prev_hash: String,
    lines: Vec<String>,
    root: String,
}

impl ReplayWriter {
    pub fn new() -> Self {
        Self {
            seq: 0,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            lines: Vec::new(),
            root: GENESIS_PREV_HASH.to_string(),
        }
    }

    /// Record one event. `ts_ms` is supplied by the caller so tests (and
    /// conformance vectors) can pin it.
    pub fn record(&mut self, kind: &str, payload: Json, ts_ms: u64) -> FlickerResult<ReplayRecord> {
        let mut event = Json::obj();
        event.insert("kind", Json::str(kind));
        event.insert("payload", payload);
        event.insert("seq", Json::int(self.seq as i64));
        event.insert("ts_ms", Json::int(ts_ms as i64));
        let event_canon = event.to_canonical()?;
        let event_hash = sha256_hex(event_canon.as_bytes());
        let prev_hash = self.prev_hash.clone();
        let chain_input = format!("{}{}", prev_hash, event_hash);
        let line_hash = sha256_hex(chain_input.as_bytes());

        let mut line = Json::obj();
        line.insert("event", event);
        line.insert("event_hash", Json::str(event_hash.clone()));
        line.insert("line_hash", Json::str(line_hash.clone()));
        line.insert("prev_hash", Json::str(prev_hash.clone()));
        line.insert("seq", Json::int(self.seq as i64));
        let line_canon = line.to_canonical()?;

        self.lines.push(line_canon.clone());
        self.prev_hash = line_hash.clone();
        self.root = line_hash.clone();
        self.seq += 1;

        Ok(ReplayRecord {
            seq: self.seq - 1,
            prev_hash,
            event_hash,
            line_hash,
            line: line_canon,
        })
    }

    pub fn root_hash(&self) -> &str {
        &self.root
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn to_jsonl(&self) -> String {
        self.lines.join("\n") + if self.lines.is_empty() { "" } else { "\n" }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainReport {
    pub ok: bool,
    pub lines: usize,
    pub root_hash: String,
    pub error: Option<String>,
}

/// Verify a JSONL chain. Checks per line:
/// 1. envelope parses; seq monotonic from 0; prev_hash links;
/// 2. event_hash == sha256(canonical(event)) — the canonical re-serialization
///    must be byte-identical (catches tampering AND serializer drift);
/// 3. line_hash == sha256(prev_hash_ascii || event_hash_ascii).
pub fn verify_chain(jsonl: &str) -> FlickerResult<ChainReport> {
    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut count: usize = 0;
    let mut root = GENESIS_PREV_HASH.to_string();
    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v = parse_json(line).map_err(|e| {
            FlickerError::validation(format!("line {}: {}", idx, e))
        })?;
        let seq = v.get("seq").and_then(|x| x.as_int()).ok_or_else(|| {
            FlickerError::validation(format!("line {}: missing seq", idx))
        })?;
        if seq != idx as i64 {
            return Ok(ChainReport {
                ok: false,
                lines: idx,
                root_hash: root.clone(),
                error: Some(format!("line {}: seq {} out of order", idx, seq)),
            });
        }
        let prev_hash = v
            .get("prev_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| FlickerError::validation(format!("line {}: missing prev_hash", idx)))?;
        if prev_hash != prev {
            return Ok(ChainReport {
                ok: false,
                lines: idx,
                root_hash: root.clone(),
                error: Some(format!("line {}: prev_hash does not link", idx)),
            });
        }
        let event = v.get("event").ok_or_else(|| {
            FlickerError::validation(format!("line {}: missing event", idx))
        })?;
        let event_canon = event.to_canonical()?;
        let event_hash = sha256_hex(event_canon.as_bytes());
        let stored_event_hash = v
            .get("event_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| FlickerError::validation(format!("line {}: missing event_hash", idx)))?;
        if event_hash != stored_event_hash {
            return Ok(ChainReport {
                ok: false,
                lines: idx,
                root_hash: root.clone(),
                error: Some(format!("line {}: event payload hash mismatch (tampered or serializer drift)", idx)),
            });
        }
        let stored_line_hash = v
            .get("line_hash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| FlickerError::validation(format!("line {}: missing line_hash", idx)))?;
        let line_hash = sha256_hex(format!("{}{}", prev_hash, event_hash).as_bytes());
        if line_hash != stored_line_hash {
            return Ok(ChainReport {
                ok: false,
                lines: idx,
                root_hash: root.clone(),
                error: Some(format!("line {}: line_hash mismatch", idx)),
            });
        }
        prev = line_hash.clone();
        root = line_hash;
        count += 1;
    }
    Ok(ChainReport { ok: true, lines: count, root_hash: root, error: None })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_writer() -> ReplayWriter {
        let mut w = ReplayWriter::new();
        let mut p1 = Json::obj();
        p1.insert("task", Json::str("demo"));
        w.record("task.received", p1, 1000).expect("rec");
        let mut p2 = Json::obj();
        p2.insert("rounds", Json::int(2));
        w.record("translation.done", p2, 1001).expect("rec");
        let p3 = Json::arr(vec![Json::str("move"), Json::str("a"), Json::str("b")]);
        w.record("plan.validated", p3, 1002).expect("rec");
        w
    }

    #[test]
    fn chain_verifies() {
        let w = sample_writer();
        let r = verify_chain(&w.to_jsonl()).expect("verify");
        assert!(r.ok);
        assert_eq!(r.lines, 3);
        assert_eq!(r.root_hash, w.root_hash());
    }

    #[test]
    fn tamper_detected() {
        let w = sample_writer();
        let mut text = w.to_jsonl();
        // flip one character inside a payload string
        let idx = text.find("demo").expect("payload");
        text.replace_range(idx..idx + 4, "demon");
        // keep valid JSON length by removing one char elsewhere is not needed:
        // parse may still succeed; hash check must fail
        if let Ok(r) = verify_chain(&text) {
            assert!(!r.ok);
        }
        // Err(_) допустим: повреждённый JSON тоже считается обнаружением
    }

    #[test]
    fn truncation_detected() {
        let w = sample_writer();
        let jsonl = w.to_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        let truncated = lines[..2].join("\n") + "\n";
        let r = verify_chain(&truncated).expect("verify");
        // Prefix chain itself is consistent — verification must report the
        // shorter root, so callers compare against the recorded root hash.
        assert!(r.ok);
        assert_eq!(r.lines, 2);
        assert_ne!(r.root_hash, w.root_hash());
    }

    #[test]
    fn reorder_detected() {
        let w = sample_writer();
        let jsonl = w.to_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        let swapped = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
        let r = verify_chain(&swapped).expect("verify");
        assert!(!r.ok);
    }
}
