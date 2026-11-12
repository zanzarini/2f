//! 2F core. Pure logic, no IO: everything here is deterministic and testable.
//!
//! See `docs/PROTOCOL.md` for the wire formats and `docs/THREAT_MODEL.md` for
//! the security claims these modules exist to uphold.

#![forbid(unsafe_code)]

pub mod action;
pub mod audit;
pub mod canonical;
pub mod keys;
pub mod passkey;
pub mod policy;
pub mod receipt;
pub mod seal;
pub mod webhook;

pub use action::{Action, Binding};
pub use policy::{ApprovalFact, ApproverKind, Decision, Policy, Requirement, Strength};
pub use receipt::{Approval, ReceiptPayload};

use sha2::{Digest, Sha256};

/// SHA-256 over a domain separation tag, a newline and the message.
pub(crate) fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(b"\n");
    h.update(msg);
    h.finalize().into()
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}
