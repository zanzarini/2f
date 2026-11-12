//! Signed webhooks. The server signs each body with its Ed25519 key, so
//! receivers verify with the public key and no shared secret exists.

use crate::keys::{self, ServerKey};
use crate::{b64, unb64};
use ed25519_dalek::VerifyingKey;

pub const WEBHOOK_TAG: &str = "2F-WEBHOOK-v1";
/// Header carrying the base64url signature.
pub const SIGNATURE_HEADER: &str = "x-2f-signature";
/// Header carrying the id of the key that signed.
pub const KEY_HEADER: &str = "x-2f-key";
/// Receivers should refuse events older than this many seconds.
pub const MAX_AGE: u64 = 300;

fn message(body: &[u8]) -> Vec<u8> {
    let mut msg = format!("{WEBHOOK_TAG}\n").into_bytes();
    msg.extend_from_slice(body);
    msg
}

pub fn sign(key: &ServerKey, body: &[u8]) -> String {
    b64(&key.sign(&message(body)))
}

pub fn verify(key: &VerifyingKey, body: &[u8], signature: &str) -> bool {
    unb64(signature).is_some_and(|sig| keys::verify(key, &message(body), &sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_signatures() {
        let key = ServerKey::generate();
        let sig = sign(&key, b"{\"event\":\"x\"}");
        assert!(verify(&key.public(), b"{\"event\":\"x\"}", &sig));
        assert!(!verify(&key.public(), b"{\"event\":\"y\"}", &sig));
        assert!(!verify(
            &ServerKey::generate().public(),
            b"{\"event\":\"x\"}",
            &sig
        ));
        assert!(!verify(&key.public(), b"{\"event\":\"x\"}", "junk"));
        // A raw signature over the body, without the tag, is not a webhook signature.
        assert!(!verify(&key.public(), b"abc", &b64(&key.sign(b"abc"))));
    }
}
