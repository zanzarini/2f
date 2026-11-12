//! Ed25519 keys: the server receipt key and approver device keys.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid key material")]
pub struct KeyError;

/// A signing key. The seed is never printed by `Debug`.
pub struct ServerKey {
    signing: SigningKey,
}

impl fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerKey({})", self.kid())
    }
}

impl ServerKey {
    pub fn generate() -> Self {
        ServerKey {
            signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    pub fn from_seed_hex(seed: &str) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = hex::decode(seed.trim())
            .map_err(|_| KeyError)?
            .try_into()
            .map_err(|_| KeyError)?;
        Ok(ServerKey {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public().as_bytes())
    }

    pub fn kid(&self) -> String {
        key_id(&self.public())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Short stable identifier of a public key.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(key.as_bytes())[..8])
}

pub fn public_from_hex(s: &str) -> Result<VerifyingKey, KeyError> {
    let bytes: [u8; 32] = hex::decode(s.trim())
        .map_err(|_| KeyError)?
        .try_into()
        .map_err(|_| KeyError)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError)
}

/// Strict verification: rejects malleable signatures and weak keys.
pub fn verify(key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let key = ServerKey::generate();
        let sig = key.sign(b"hello");
        assert!(verify(&key.public(), b"hello", &sig));
        assert!(!verify(&key.public(), b"hellp", &sig));
        assert!(!verify(&ServerKey::generate().public(), b"hello", &sig));
        assert!(!verify(&key.public(), b"hello", &sig[..63]));
    }

    #[test]
    fn seed_roundtrip_and_debug_hides_seed() {
        let key = ServerKey::generate();
        let again = ServerKey::from_seed_hex(&key.seed_hex()).unwrap();
        assert_eq!(key.kid(), again.kid());
        assert_eq!(public_from_hex(&key.public_hex()).unwrap(), key.public());
        assert!(!format!("{key:?}").contains(&key.seed_hex()));
        assert!(ServerKey::from_seed_hex("abcd").is_err());
    }
}
