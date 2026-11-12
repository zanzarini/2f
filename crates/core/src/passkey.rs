//! WebAuthn (passkey) verification, following the W3C Web Authentication
//! specification, sections 7.1 (registration) and 7.2 (assertion).
//!
//! The WebAuthn challenge is not a random nonce here: it is the binding hash,
//! so the authenticator's signature covers the exact action being approved.
//! Attestation is not evaluated (`attestation: "none"`): what makes an
//! enrolled key trustworthy is who was allowed to enroll it.

use crate::{b64, canonical, unb64};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// COSE algorithm identifier for ECDSA P-256 with SHA-256.
pub const ALG_ES256: i64 = -7;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_ATTESTED_DATA: u8 = 0x40;

/// Who the passkeys belong to: the domain and the exact web origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    pub id: String,
    pub origin: String,
}

impl RelyingParty {
    /// Derives the relying party from the server's public URL.
    pub fn from_url(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        if scheme != "https" && scheme != "http" {
            return None;
        }
        let authority = rest.split('/').next()?;
        let host = authority.rsplit_once(':').map_or(authority, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                authority
            }
        });
        if host.is_empty() || authority.contains('@') {
            return None;
        }
        Some(RelyingParty {
            id: host.to_owned(),
            origin: format!("{scheme}://{authority}"),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasskeyError {
    #[error("malformed passkey response")]
    Malformed,
    #[error("passkey response is for a different operation")]
    WrongType,
    #[error("passkey response does not cover this challenge")]
    WrongChallenge,
    #[error("passkey response came from a different website")]
    WrongOrigin,
    #[error("the device did not verify the user (PIN or biometrics)")]
    UserNotVerified,
    #[error("unsupported or invalid public key")]
    BadKey,
    #[error("passkey signature is invalid")]
    BadSignature,
    #[error("passkey signature counter went backwards; the key may have been cloned")]
    Counter,
}

/// What a browser returns from `navigator.credentials.get`, base64url encoded.
/// This is also the proof stored in a receipt for a passkey approval.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssertionProof {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

impl AssertionProof {
    /// Compact form carried in `Approval::sig`.
    pub fn encode(&self) -> String {
        let value = serde_json::to_value(self).expect("proof is plain data");
        b64(canonical::to_canonical(&value)
            .expect("proof has no floats")
            .as_bytes())
    }

    pub fn decode(encoded: &str) -> Option<Self> {
        let bytes = unb64(encoded)?;
        let value = canonical::parse_strict(std::str::from_utf8(&bytes).ok()?).ok()?;
        serde_json::from_value(value).ok()
    }
}

struct AuthenticatorData<'a> {
    counter: u32,
    credential_id: Option<&'a [u8]>,
}

fn parse_authenticator_data<'a>(
    data: &'a [u8],
    rp: &RelyingParty,
) -> Result<AuthenticatorData<'a>, PasskeyError> {
    if data.len() < 37 {
        return Err(PasskeyError::Malformed);
    }
    let expected_rp = Sha256::digest(rp.id.as_bytes());
    if !bool::from(data[..32].ct_eq(expected_rp.as_slice())) {
        return Err(PasskeyError::WrongOrigin);
    }
    let flags = data[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return Err(PasskeyError::UserNotVerified);
    }
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let credential_id = if flags & FLAG_ATTESTED_DATA != 0 {
        // aaguid (16) | credential id length (2) | credential id | public key
        let len_bytes = data.get(53..55).ok_or(PasskeyError::Malformed)?;
        let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
        let id = data.get(55..55 + len).ok_or(PasskeyError::Malformed)?;
        if id.is_empty() {
            return Err(PasskeyError::Malformed);
        }
        Some(id)
    } else {
        None
    };
    Ok(AuthenticatorData {
        counter,
        credential_id,
    })
}

fn check_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    challenge: &[u8],
    rp: &RelyingParty,
) -> Result<(), PasskeyError> {
    let text = std::str::from_utf8(client_data_json).map_err(|_| PasskeyError::Malformed)?;
    let value = canonical::parse_strict(text).map_err(|_| PasskeyError::Malformed)?;
    let field = |name: &str| value.get(name).and_then(Value::as_str);
    if field("type") != Some(expected_type) {
        return Err(PasskeyError::WrongType);
    }
    let got = field("challenge")
        .and_then(unb64)
        .ok_or(PasskeyError::Malformed)?;
    if !bool::from(got.as_slice().ct_eq(challenge)) {
        return Err(PasskeyError::WrongChallenge);
    }
    if field("origin") != Some(rp.origin.as_str()) {
        return Err(PasskeyError::WrongOrigin);
    }
    if value.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(PasskeyError::WrongOrigin);
    }
    Ok(())
}

/// True when `spki_der` is a P-256 public key this module can verify with.
pub fn valid_public_key(spki_der: &[u8]) -> bool {
    VerifyingKey::from_public_key_der(spki_der).is_ok()
}

/// Verifies a registration response. Returns the credential id chosen by the
/// authenticator.
pub fn verify_registration(
    rp: &RelyingParty,
    challenge: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    spki_der: &[u8],
    algorithm: i64,
) -> Result<Vec<u8>, PasskeyError> {
    check_client_data(client_data_json, "webauthn.create", challenge, rp)?;
    let parsed = parse_authenticator_data(authenticator_data, rp)?;
    let credential_id = parsed.credential_id.ok_or(PasskeyError::Malformed)?;
    if algorithm != ALG_ES256 || !valid_public_key(spki_der) {
        return Err(PasskeyError::BadKey);
    }
    Ok(credential_id.to_vec())
}

/// Verifies an assertion over `challenge`. Returns the signature counter.
pub fn verify_assertion(
    rp: &RelyingParty,
    spki_der: &[u8],
    challenge: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
) -> Result<u32, PasskeyError> {
    check_client_data(client_data_json, "webauthn.get", challenge, rp)?;
    let parsed = parse_authenticator_data(authenticator_data, rp)?;
    let key = VerifyingKey::from_public_key_der(spki_der).map_err(|_| PasskeyError::BadKey)?;
    let signature = Signature::from_der(signature_der).map_err(|_| PasskeyError::BadSignature)?;
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&signed, &signature)
        .map_err(|_| PasskeyError::BadSignature)?;
    Ok(parsed.counter)
}

/// Verifies an encoded proof. Convenience for callers holding base64url text.
pub fn verify_proof(
    rp: &RelyingParty,
    spki_der: &[u8],
    challenge: &[u8],
    proof: &AssertionProof,
) -> Result<u32, PasskeyError> {
    let part = |s: &str| unb64(s).ok_or(PasskeyError::Malformed);
    verify_assertion(
        rp,
        spki_der,
        challenge,
        &part(&proof.authenticator_data)?,
        &part(&proof.client_data_json)?,
        &part(&proof.signature)?,
    )
}

/// Signature counters must grow, except for authenticators that never count
/// (synced passkeys report zero forever).
pub fn check_counter(stored: u32, received: u32) -> Result<(), PasskeyError> {
    if (stored != 0 || received != 0) && received <= stored {
        return Err(PasskeyError::Counter);
    }
    Ok(())
}

/// A software authenticator, for tests in this crate and its dependents.
pub mod testing {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    pub struct SoftAuthenticator {
        key: SigningKey,
        pub credential_id: Vec<u8>,
        pub counter: u32,
        /// Set to false to simulate a device that skipped PIN or biometrics.
        pub user_verified: bool,
    }

    impl Default for SoftAuthenticator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SoftAuthenticator {
        pub fn new() -> Self {
            use rand::RngCore;
            let mut credential_id = vec![0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut credential_id);
            SoftAuthenticator {
                key: SigningKey::random(&mut rand::rngs::OsRng),
                credential_id,
                counter: 0,
                user_verified: true,
            }
        }

        pub fn public_key_der(&self) -> Vec<u8> {
            self.key
                .verifying_key()
                .to_public_key_der()
                .expect("valid key")
                .as_bytes()
                .to_vec()
        }

        fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::json!({ "type": kind, "challenge": b64(challenge), "origin": origin, "crossOrigin": false })
                .to_string()
                .into_bytes()
        }

        fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            let mut flags = FLAG_USER_PRESENT;
            if self.user_verified {
                flags |= FLAG_USER_VERIFIED;
            }
            if attested {
                flags |= FLAG_ATTESTED_DATA;
            }
            data.push(flags);
            data.extend_from_slice(&self.counter.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0u8; 16]);
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&[0xa0]); // stand in for the COSE key
            }
            data
        }

        /// Returns `(authenticator_data, client_data_json)` for a registration.
        pub fn register(&self, rp_id: &str, origin: &str, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            (
                self.authenticator_data(rp_id, true),
                Self::client_data("webauthn.create", challenge, origin),
            )
        }

        /// Signs `challenge` as the browser at `origin` would.
        pub fn assert(&mut self, rp_id: &str, origin: &str, challenge: &[u8]) -> AssertionProof {
            let authenticator_data = self.authenticator_data(rp_id, false);
            let client_data_json = Self::client_data("webauthn.get", challenge, origin);
            let mut signed = authenticator_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data_json));
            let signature: Signature = self.key.sign(&signed);
            AssertionProof {
                authenticator_data: b64(&authenticator_data),
                client_data_json: b64(&client_data_json),
                signature: b64(signature.to_der().as_bytes()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::SoftAuthenticator;
    use super::*;

    fn rp() -> RelyingParty {
        RelyingParty::from_url("https://2f.example.com/anything").unwrap()
    }

    #[test]
    fn relying_party_from_url() {
        assert_eq!(
            rp(),
            RelyingParty {
                id: "2f.example.com".into(),
                origin: "https://2f.example.com".into()
            }
        );
        let local = RelyingParty::from_url("http://localhost:8722").unwrap();
        assert_eq!(
            (local.id.as_str(), local.origin.as_str()),
            ("localhost", "http://localhost:8722")
        );
        for bad in [
            "localhost:8722",
            "ftp://x.com",
            "https://",
            "https://user@evil.com",
        ] {
            assert!(RelyingParty::from_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn registration_and_assertion_verify() {
        let rp = rp();
        let mut device = SoftAuthenticator::new();
        let (auth_data, client_data) = device.register(&rp.id, &rp.origin, b"enroll-challenge");
        let id = verify_registration(
            &rp,
            b"enroll-challenge",
            &auth_data,
            &client_data,
            &device.public_key_der(),
            ALG_ES256,
        )
        .unwrap();
        assert_eq!(id, device.credential_id);

        let challenge = [7u8; 32];
        let proof = device.assert(&rp.id, &rp.origin, &challenge);
        assert_eq!(
            verify_proof(&rp, &device.public_key_der(), &challenge, &proof),
            Ok(0)
        );
        assert_eq!(AssertionProof::decode(&proof.encode()), Some(proof));
    }

    #[test]
    fn assertion_is_bound_to_challenge_origin_key_and_type() {
        let rp = rp();
        let mut device = SoftAuthenticator::new();
        let key = device.public_key_der();
        let challenge = [7u8; 32];
        let proof = device.assert(&rp.id, &rp.origin, &challenge);

        // Approval of one action presented for another.
        assert_eq!(
            verify_proof(&rp, &key, &[8u8; 32], &proof),
            Err(PasskeyError::WrongChallenge)
        );
        // Signed on a phishing site.
        let phished = device.assert(&rp.id, "https://2f.example.com.evil.io", &challenge);
        assert_eq!(
            verify_proof(&rp, &key, &challenge, &phished),
            Err(PasskeyError::WrongOrigin)
        );
        let other_rp = device.assert("evil.io", &rp.origin, &challenge);
        assert_eq!(
            verify_proof(&rp, &key, &challenge, &other_rp),
            Err(PasskeyError::WrongOrigin)
        );
        // Another device's key.
        let stranger = SoftAuthenticator::new().public_key_der();
        assert_eq!(
            verify_proof(&rp, &stranger, &challenge, &proof),
            Err(PasskeyError::BadSignature)
        );
        // A registration response replayed as an assertion.
        let (auth_data, client_data) = device.register(&rp.id, &rp.origin, &challenge);
        let replay = AssertionProof {
            authenticator_data: b64(&auth_data),
            client_data_json: b64(&client_data),
            signature: proof.signature.clone(),
        };
        assert_eq!(
            verify_proof(&rp, &key, &challenge, &replay),
            Err(PasskeyError::WrongType)
        );
        // Client data edited after signing.
        let mut edited = proof.clone();
        let json = String::from_utf8(unb64(&proof.client_data_json).unwrap()).unwrap();
        edited.client_data_json = b64(json.replace("false", "false ").as_bytes());
        assert_eq!(
            verify_proof(&rp, &key, &challenge, &edited),
            Err(PasskeyError::BadSignature)
        );
        // Authenticator data edited after signing (counter bumped).
        let mut edited = proof.clone();
        let mut bytes = unb64(&proof.authenticator_data).unwrap();
        bytes[36] ^= 1;
        edited.authenticator_data = b64(&bytes);
        assert_eq!(
            verify_proof(&rp, &key, &challenge, &edited),
            Err(PasskeyError::BadSignature)
        );
    }

    #[test]
    fn user_verification_is_required() {
        let rp = rp();
        let mut device = SoftAuthenticator::new();
        device.user_verified = false;
        let proof = device.assert(&rp.id, &rp.origin, &[1u8; 32]);
        assert_eq!(
            verify_proof(&rp, &device.public_key_der(), &[1u8; 32], &proof),
            Err(PasskeyError::UserNotVerified)
        );
        let (auth_data, client_data) = device.register(&rp.id, &rp.origin, b"c");
        assert_eq!(
            verify_registration(
                &rp,
                b"c",
                &auth_data,
                &client_data,
                &device.public_key_der(),
                ALG_ES256
            ),
            Err(PasskeyError::UserNotVerified)
        );
    }

    #[test]
    fn registration_rejects_bad_keys_and_garbage() {
        let rp = rp();
        let device = SoftAuthenticator::new();
        let (auth_data, client_data) = device.register(&rp.id, &rp.origin, b"c");
        let key = device.public_key_der();
        assert_eq!(
            verify_registration(&rp, b"c", &auth_data, &client_data, b"junk", ALG_ES256),
            Err(PasskeyError::BadKey)
        );
        assert_eq!(
            verify_registration(&rp, b"c", &auth_data, &client_data, &key, -8),
            Err(PasskeyError::BadKey)
        );
        assert_eq!(
            verify_registration(&rp, b"d", &auth_data, &client_data, &key, ALG_ES256),
            Err(PasskeyError::WrongChallenge)
        );
        assert_eq!(
            verify_registration(&rp, b"c", &auth_data[..36], &client_data, &key, ALG_ES256),
            Err(PasskeyError::Malformed)
        );
        assert_eq!(
            verify_registration(&rp, b"c", &auth_data[..54], &client_data, &key, ALG_ES256),
            Err(PasskeyError::Malformed)
        );
        assert_eq!(
            verify_registration(&rp, b"c", &auth_data, b"not json", &key, ALG_ES256),
            Err(PasskeyError::Malformed)
        );
    }

    #[test]
    fn counter_rules() {
        assert!(check_counter(0, 0).is_ok());
        assert!(check_counter(0, 1).is_ok());
        assert!(check_counter(5, 6).is_ok());
        assert_eq!(check_counter(5, 5), Err(PasskeyError::Counter));
        assert_eq!(check_counter(5, 0), Err(PasskeyError::Counter));
    }
}
