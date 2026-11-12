//! Seals: the server signs the rows that grant power (policies, API keys,
//! approver credentials) and refuses to use a row whose seal does not verify.
//!
//! Without seals, write access to the database would be enough to enroll an
//! approver or loosen a policy. With them the attacker also needs the signing
//! key, which is not in the database.

use crate::keys::{self, ServerKey};
use crate::{b64, canonical, unb64};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;

pub const SEAL_TAG: &str = "2F-SEAL-v1";

/// The exact bytes a seal signs for a set of fields.
pub fn message(fields: &Value) -> Vec<u8> {
    let text = canonical::to_canonical(fields).expect("sealed fields have no floats");
    format!("{SEAL_TAG}\n{text}").into_bytes()
}

pub fn sign(key: &ServerKey, fields: &Value) -> String {
    b64(&key.sign(&message(fields)))
}

pub fn verify(key: &VerifyingKey, fields: &Value, seal: &str) -> bool {
    unb64(seal).is_some_and(|sig| keys::verify(key, &message(fields), &sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_seal_covers_every_field_and_only_its_key_makes_it() {
        let key = ServerKey::generate();
        let fields =
            json!({ "t": "credential", "project": "p", "approver": "alice", "public_key": "aa" });
        let seal = sign(&key, &fields);
        assert!(verify(&key.public(), &fields, &seal));
        // Key order is irrelevant, content is not.
        let reordered =
            json!({ "public_key": "aa", "approver": "alice", "project": "p", "t": "credential" });
        assert!(verify(&key.public(), &reordered, &seal));
        for changed in [
            json!({ "t": "credential", "project": "p", "approver": "mallory", "public_key": "aa" }),
            json!({ "t": "credential", "project": "p", "approver": "alice", "public_key": "bb" }),
            json!({ "t": "apikey", "project": "p", "approver": "alice", "public_key": "aa" }),
        ] {
            assert!(!verify(&key.public(), &changed, &seal));
        }
        assert!(!verify(&ServerKey::generate().public(), &fields, &seal));
        assert!(!verify(&key.public(), &fields, ""));
    }
}
