//! Tamper evident audit log: a hash chain with signed checkpoints.
//!
//! The chain detects edits, insertions and deletions in the middle. Cutting
//! entries off the end is only detected against a checkpoint kept somewhere
//! else, which is why checkpoints are signed and meant to be exported.

use crate::canonical::{self, CanonError};
use crate::keys::{self, ServerKey};
use crate::{b64, tagged_hash, unb64};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const AUDIT_TAG: &str = "2F-AUDIT-v1";
pub const CHECKPOINT_TAG: &str = "2F-CHECKPOINT-v1";
pub const ENTRY_SIG_TAG: &str = "2F-AUDIT-SIG-v1";

/// Signs an entry hash. The chain alone is tamper evident but anyone can
/// extend it; signed entries can only be appended by the key holder.
pub fn sign_entry(key: &ServerKey, hash: &str) -> String {
    b64(&key.sign(format!("{ENTRY_SIG_TAG}\n{hash}").as_bytes()))
}

pub fn entry_signature_valid(key: &VerifyingKey, hash: &str, sig: &str) -> bool {
    unb64(sig)
        .is_some_and(|sig| keys::verify(key, format!("{ENTRY_SIG_TAG}\n{hash}").as_bytes(), &sig))
}
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub data: Value,
    pub prev: String,
    pub hash: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("entry {seq}: expected sequence number {expected}")]
    Sequence { seq: u64, expected: u64 },
    #[error("entry {seq}: does not link to the previous entry")]
    Broken { seq: u64 },
    #[error("entry {seq}: content does not match its hash")]
    Altered { seq: u64 },
    #[error("checkpoint at {seq} does not match the log")]
    Checkpoint { seq: u64 },
}

fn entry_hash(
    seq: u64,
    ts: u64,
    kind: &str,
    data: &Value,
    prev: &str,
) -> Result<String, CanonError> {
    let body = json!({ "seq": seq, "ts": ts, "kind": kind, "data": data, "prev": prev });
    Ok(hex::encode(tagged_hash(
        AUDIT_TAG,
        canonical::to_canonical(&body)?.as_bytes(),
    )))
}

/// Builds the entry that follows `prev` (`None` for the first one).
pub fn next_entry(
    prev: Option<(u64, &str)>,
    ts: u64,
    kind: &str,
    data: Value,
) -> Result<Entry, CanonError> {
    let (seq, prev_hash) = match prev {
        Some((seq, hash)) => (seq + 1, hash),
        None => (1, GENESIS),
    };
    let hash = entry_hash(seq, ts, kind, &data, prev_hash)?;
    Ok(Entry {
        seq,
        ts,
        kind: kind.to_owned(),
        data,
        prev: prev_hash.to_owned(),
        hash,
    })
}

/// Verifies a whole chain from the first entry. Returns the head `(seq, hash)`.
pub fn verify_chain<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Result<Option<(u64, String)>, AuditError> {
    let mut head: Option<(u64, String)> = None;
    for entry in entries {
        let (expected_seq, expected_prev) = match &head {
            Some((seq, hash)) => (seq + 1, hash.as_str()),
            None => (1, GENESIS),
        };
        if entry.seq != expected_seq {
            return Err(AuditError::Sequence {
                seq: entry.seq,
                expected: expected_seq,
            });
        }
        if entry.prev != expected_prev {
            return Err(AuditError::Broken { seq: entry.seq });
        }
        let recomputed = entry_hash(entry.seq, entry.ts, &entry.kind, &entry.data, &entry.prev)
            .map_err(|_| AuditError::Altered { seq: entry.seq })?;
        if recomputed != entry.hash {
            return Err(AuditError::Altered { seq: entry.seq });
        }
        head = Some((entry.seq, entry.hash.clone()));
    }
    Ok(head)
}

/// A signed statement: "at `ts` the log had `seq` entries ending in `hash`".
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub seq: u64,
    pub hash: String,
    pub ts: u64,
    pub kid: String,
    pub sig: String,
}

fn checkpoint_message(seq: u64, hash: &str, ts: u64) -> Vec<u8> {
    let body = json!({ "seq": seq, "hash": hash, "ts": ts });
    let text = canonical::to_canonical(&body).expect("checkpoint has no floats");
    format!("{CHECKPOINT_TAG}\n{text}").into_bytes()
}

impl Checkpoint {
    pub fn sign(seq: u64, hash: &str, ts: u64, key: &ServerKey) -> Self {
        let sig = key.sign(&checkpoint_message(seq, hash, ts));
        Checkpoint {
            seq,
            hash: hash.to_owned(),
            ts,
            kid: key.kid(),
            sig: b64(&sig),
        }
    }

    pub fn signature_valid(&self, key: &VerifyingKey) -> bool {
        unb64(&self.sig).is_some_and(|sig| {
            keys::verify(
                key,
                &checkpoint_message(self.seq, &self.hash, self.ts),
                &sig,
            )
        })
    }

    /// Checks the checkpoint against a chain that already passed
    /// `verify_chain`: the entry at `seq` must exist and carry `hash`.
    pub fn matches(&self, entries: &[Entry]) -> Result<(), AuditError> {
        let found = self
            .seq
            .checked_sub(1)
            .and_then(|i| entries.get(usize::try_from(i).ok()?))
            .is_some_and(|e| e.seq == self.seq && e.hash == self.hash);
        if found {
            Ok(())
        } else {
            Err(AuditError::Checkpoint { seq: self.seq })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<Entry> {
        let mut out: Vec<Entry> = Vec::new();
        for i in 0..n {
            let prev = out.last().map(|e| (e.seq, e.hash.as_str()));
            let entry = next_entry(prev, 1_000 + i, "test", json!({ "i": i })).unwrap();
            out.push(entry);
        }
        out
    }

    #[test]
    fn intact_chain_verifies() {
        assert_eq!(verify_chain(&chain(0)).unwrap(), None);
        let c = chain(5);
        assert_eq!(verify_chain(&c).unwrap(), Some((5, c[4].hash.clone())));
    }

    #[test]
    fn every_kind_of_tampering_is_detected() {
        let c = chain(5);

        let mut edited = c.clone();
        edited[2].data = json!({ "i": 99 });
        assert_eq!(verify_chain(&edited), Err(AuditError::Altered { seq: 3 }));

        let mut edited = c.clone();
        edited[2].ts += 1;
        assert_eq!(verify_chain(&edited), Err(AuditError::Altered { seq: 3 }));

        let mut edited = c.clone();
        edited[2].kind = "other".into();
        assert_eq!(verify_chain(&edited), Err(AuditError::Altered { seq: 3 }));

        // Editing and recomputing the hash breaks the link from the next entry.
        let mut rehashed = c.clone();
        rehashed[2] = next_entry(
            Some((2, c[1].hash.as_str())),
            1_002,
            "test",
            json!({ "i": 99 }),
        )
        .unwrap();
        assert_eq!(verify_chain(&rehashed), Err(AuditError::Broken { seq: 4 }));

        let mut deleted = c.clone();
        deleted.remove(2);
        assert_eq!(
            verify_chain(&deleted),
            Err(AuditError::Sequence {
                seq: 4,
                expected: 3
            })
        );

        let mut swapped = c.clone();
        swapped.swap(1, 2);
        assert!(verify_chain(&swapped).is_err());

        let without_first = &c[1..];
        assert!(verify_chain(without_first).is_err());
    }

    #[test]
    fn checkpoints_catch_truncation_and_rewrites() {
        let key = ServerKey::generate();
        let c = chain(5);
        let cp = Checkpoint::sign(5, &c[4].hash, 2_000, &key);
        assert!(cp.signature_valid(&key.public()));
        assert!(cp.matches(&c).is_ok());

        // The tail was cut off: the chain alone still verifies, the checkpoint does not.
        let truncated = &c[..3];
        assert!(verify_chain(truncated).is_ok());
        assert_eq!(
            cp.matches(truncated),
            Err(AuditError::Checkpoint { seq: 5 })
        );

        // The whole history was rewritten consistently.
        let mut rewritten = chain(4);
        let prev = rewritten.last().map(|e| (e.seq, e.hash.clone())).unwrap();
        rewritten.push(next_entry(Some((prev.0, &prev.1)), 9, "test", json!({})).unwrap());
        assert!(verify_chain(&rewritten).is_ok());
        assert_eq!(
            cp.matches(&rewritten),
            Err(AuditError::Checkpoint { seq: 5 })
        );

        // A checkpoint cannot be edited or signed by someone else.
        let mut forged = cp.clone();
        forged.hash = rewritten[4].hash.clone();
        assert!(!forged.signature_valid(&key.public()));
        assert!(!cp.signature_valid(&ServerKey::generate().public()));
        let zero = Checkpoint::sign(0, GENESIS, 1, &key);
        assert!(zero.matches(&c).is_err());
    }
}
