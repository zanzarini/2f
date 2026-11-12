//! Signed receipts: the proof a client holds before executing an action.

use crate::action::{Action, Binding};
use crate::canonical;
use crate::keys::{self, ServerKey};
use crate::policy::{ApprovalFact, ApproverKind, Strength};
use crate::{b64, unb64};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

pub const RECEIPT_TAG: &str = "2F-RECEIPT-v1";
/// Tolerated clock difference between server and verifier, in seconds.
pub const CLOCK_SKEW: u64 = 60;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptDecision {
    /// A rule allowed the action without approval.
    Allow,
    /// Approvers satisfied the requirements of a rule.
    Approved,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approver: String,
    pub kind: ApproverKind,
    pub strength: Strength,
    /// The approver's proof over the binding hash, base64url. For `ed25519`
    /// and `cosigner` this is the raw 64 byte signature.
    pub sig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    pub v: u8,
    pub id: String,
    pub project: String,
    pub challenge: String,
    pub action_hash: String,
    pub decision: ReceiptDecision,
    pub rule: String,
    pub approvals: Vec<Approval>,
    pub binding_expires_at: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub kid: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("receipt is malformed")]
    Malformed,
    #[error("receipt was signed by an unknown key")]
    UnknownKey,
    #[error("receipt signature is invalid")]
    BadSignature,
    #[error("receipt has expired")]
    Expired,
    #[error("receipt is not valid yet")]
    NotYetValid,
    #[error("receipt was issued for a different action")]
    ActionMismatch,
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RECEIPT_TAG.len() + 1 + payload.len());
    msg.extend_from_slice(RECEIPT_TAG.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(payload);
    msg
}

impl ReceiptPayload {
    /// Signs the receipt. `self.kid` must name `key`.
    pub fn issue(&self, key: &ServerKey) -> String {
        debug_assert_eq!(self.kid, key.kid());
        let value = serde_json::to_value(self).expect("receipt is plain data");
        let payload = canonical::to_canonical(&value).expect("receipt has no floats");
        let sig = key.sign(&signed_message(payload.as_bytes()));
        format!("{}.{}", b64(payload.as_bytes()), b64(&sig))
    }

    /// The binding the approvers of this receipt signed.
    pub fn binding(&self) -> Binding {
        Binding::new(
            &self.project,
            &self.challenge,
            &self.action_hash,
            self.binding_expires_at,
        )
    }

    /// Approvals whose signature verifies against a key the caller pinned.
    ///
    /// The receipt signature proves the 2F server vouches for the approvals.
    /// This proves it without trusting the server: only the holder of the
    /// pinned private key can have produced the signature for this binding.
    /// Approvers that are not pinned are ignored.
    pub fn pinned_approvals(&self, pinned: &BTreeMap<String, VerifyingKey>) -> Vec<ApprovalFact> {
        let binding_hash = self.binding().hash();
        self.approvals
            .iter()
            .filter(|a| matches!(a.kind, ApproverKind::Ed25519 | ApproverKind::Cosigner))
            .filter(|a| {
                let (Some(key), Some(sig)) = (pinned.get(&a.approver), unb64(&a.sig)) else {
                    return false;
                };
                keys::verify(key, &binding_hash, &sig)
            })
            .map(|a| ApprovalFact {
                approver: a.approver.clone(),
                kind: a.kind,
            })
            .collect()
    }
}

/// Checks signature and validity window, without looking at any action.
pub fn verify_signature(
    token: &str,
    lookup: &dyn Fn(&str) -> Option<VerifyingKey>,
    now: u64,
) -> Result<ReceiptPayload, ReceiptError> {
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(ReceiptError::Malformed)?;
    let payload_bytes = unb64(payload_b64).ok_or(ReceiptError::Malformed)?;
    let sig = unb64(sig_b64).ok_or(ReceiptError::Malformed)?;
    let text = std::str::from_utf8(&payload_bytes).map_err(|_| ReceiptError::Malformed)?;
    let value = canonical::parse_strict(text).map_err(|_| ReceiptError::Malformed)?;
    let payload: ReceiptPayload =
        serde_json::from_value(value).map_err(|_| ReceiptError::Malformed)?;
    if payload.v != 1 {
        return Err(ReceiptError::Malformed);
    }
    let key = lookup(&payload.kid).ok_or(ReceiptError::UnknownKey)?;
    if !keys::verify(&key, &signed_message(&payload_bytes), &sig) {
        return Err(ReceiptError::BadSignature);
    }
    if now > payload.expires_at {
        return Err(ReceiptError::Expired);
    }
    if payload.issued_at > now.saturating_add(CLOCK_SKEW) {
        return Err(ReceiptError::NotYetValid);
    }
    Ok(payload)
}

/// Full verification: signature, validity window, and that the receipt was
/// issued for exactly `action`.
pub fn verify(
    token: &str,
    lookup: &dyn Fn(&str) -> Option<VerifyingKey>,
    action: &Action,
    now: u64,
) -> Result<ReceiptPayload, ReceiptError> {
    let payload = verify_signature(token, lookup, now)?;
    let expected = action
        .hash_hex()
        .map_err(|_| ReceiptError::ActionMismatch)?;
    if !bool::from(expected.as_bytes().ct_eq(payload.action_hash.as_bytes())) {
        return Err(ReceiptError::ActionMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action() -> Action {
        Action::parse(r#"{"type":"withdraw","amount":"10","asset":"USDT","destination":"0xaaa"}"#)
            .unwrap()
    }

    fn payload(key: &ServerKey, approvals: Vec<Approval>) -> ReceiptPayload {
        ReceiptPayload {
            v: 1,
            id: "r1".into(),
            project: "p1".into(),
            challenge: "c1".into(),
            action_hash: action().hash_hex().unwrap(),
            decision: ReceiptDecision::Approved,
            rule: "rule".into(),
            approvals,
            binding_expires_at: 2_000,
            issued_at: 1_000,
            expires_at: 1_300,
            kid: key.kid(),
        }
    }

    fn lookup(key: &ServerKey) -> impl Fn(&str) -> Option<VerifyingKey> + '_ {
        move |kid| (kid == key.kid()).then(|| key.public())
    }

    #[test]
    fn valid_receipt_verifies() {
        let key = ServerKey::generate();
        let token = payload(&key, vec![]).issue(&key);
        let got = verify(&token, &lookup(&key), &action(), 1_100).unwrap();
        assert_eq!(got, payload(&key, vec![]));
    }

    #[test]
    fn receipt_is_bound_to_the_action() {
        let key = ServerKey::generate();
        let token = payload(&key, vec![]).issue(&key);
        for other in [
            r#"{"type":"withdraw","amount":"11","asset":"USDT","destination":"0xaaa"}"#,
            r#"{"type":"withdraw","amount":"10","asset":"USDT","destination":"0xbbb"}"#,
        ] {
            let other = Action::parse(other).unwrap();
            assert_eq!(
                verify(&token, &lookup(&key), &other, 1_100),
                Err(ReceiptError::ActionMismatch)
            );
        }
    }

    #[test]
    fn validity_window_is_enforced() {
        let key = ServerKey::generate();
        let token = payload(&key, vec![]).issue(&key);
        let at = |now| verify(&token, &lookup(&key), &action(), now);
        assert!(at(1_300).is_ok());
        assert_eq!(at(1_301), Err(ReceiptError::Expired));
        assert!(at(1_000 - CLOCK_SKEW).is_ok());
        assert_eq!(at(1_000 - CLOCK_SKEW - 1), Err(ReceiptError::NotYetValid));
    }

    #[test]
    fn forged_or_altered_receipts_fail() {
        let key = ServerKey::generate();
        let attacker = ServerKey::generate();
        let token = payload(&key, vec![]).issue(&key);

        // Signed by a key the verifier does not know.
        let mut forged = payload(&attacker, vec![]);
        assert_eq!(
            verify(&forged.issue(&attacker), &lookup(&key), &action(), 1_100),
            Err(ReceiptError::UnknownKey)
        );
        // Signed by the attacker but claiming the real key id.
        forged.kid = key.kid();
        let value = serde_json::to_value(&forged).unwrap();
        let body = canonical::to_canonical(&value).unwrap();
        let fake = format!(
            "{}.{}",
            b64(body.as_bytes()),
            b64(&attacker.sign(&signed_message(body.as_bytes())))
        );
        assert_eq!(
            verify(&fake, &lookup(&key), &action(), 1_100),
            Err(ReceiptError::BadSignature)
        );
        // Real signature moved onto an edited payload.
        let (_, sig) = token.split_once('.').unwrap();
        let mut edited = payload(&key, vec![]);
        edited.expires_at = 9_999_999;
        let value = serde_json::to_value(&edited).unwrap();
        let body = canonical::to_canonical(&value).unwrap();
        let spliced = format!("{}.{}", b64(body.as_bytes()), sig);
        assert_eq!(
            verify(&spliced, &lookup(&key), &action(), 1_100),
            Err(ReceiptError::BadSignature)
        );
        // Garbage.
        for junk in ["", ".", "abc", "a.b", "!!!.???"] {
            assert_eq!(
                verify(junk, &lookup(&key), &action(), 1_100),
                Err(ReceiptError::Malformed)
            );
        }
    }

    #[test]
    fn a_receipt_signature_is_not_valid_for_other_purposes() {
        // The same key signing the bare payload (no tag) must not verify.
        let key = ServerKey::generate();
        let value = serde_json::to_value(payload(&key, vec![])).unwrap();
        let body = canonical::to_canonical(&value).unwrap();
        let untagged = format!(
            "{}.{}",
            b64(body.as_bytes()),
            b64(&key.sign(body.as_bytes()))
        );
        assert_eq!(
            verify(&untagged, &lookup(&key), &action(), 1_100),
            Err(ReceiptError::BadSignature)
        );
    }

    #[test]
    fn pinned_approvals_do_not_trust_the_server() {
        let server = ServerKey::generate();
        let alice = ServerKey::generate();
        let mallory = ServerKey::generate();
        let draft = payload(&server, vec![]);
        let binding_hash = draft.binding().hash();
        let approval = |name: &str, signer: &ServerKey| Approval {
            approver: name.into(),
            kind: ApproverKind::Ed25519,
            strength: Strength::Strong,
            sig: b64(&signer.sign(&binding_hash)),
        };
        let pinned = BTreeMap::from([("alice".to_string(), alice.public())]);

        let honest = payload(&server, vec![approval("alice", &alice)]);
        assert_eq!(honest.pinned_approvals(&pinned).len(), 1);

        // A compromised server claims alice approved, with someone else's signature.
        let lying = payload(&server, vec![approval("alice", &mallory)]);
        assert!(lying.pinned_approvals(&pinned).is_empty());

        // Alice's signature for another challenge does not transfer.
        let mut other = payload(&server, vec![approval("alice", &alice)]);
        other.challenge = "c2".into();
        assert!(other.pinned_approvals(&pinned).is_empty());

        // Unpinned approvers are ignored.
        let unknown = payload(&server, vec![approval("bob", &mallory)]);
        assert!(unknown.pinned_approvals(&pinned).is_empty());
    }
}
