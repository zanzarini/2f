//! Passkey enrollment and approval, driven by a software authenticator.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::json;
use twof_core::keys::ServerKey;
use twof_core::passkey::testing::SoftAuthenticator;
use twof_core::passkey::ALG_ES256;
use twof_server::service::ENROLLMENT_TTL;
use twof_server::{Config, Error, Proof, Registration, Service};

const T0: u64 = 1_800_000_000;
const RP_ID: &str = "2f.example.com";
const ORIGIN: &str = "https://2f.example.com";
const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "passkey only", "when": {},
      "then": { "decision": "require", "requirements": [ { "count": 1, "kinds": ["passkey"] } ] } } ] }"#;

fn setup() -> (Service, String) {
    let config = Config {
        public_url: ORIGIN.into(),
        ..Config::default()
    };
    let svc = Service::open_in_memory(ServerKey::generate(), config).unwrap();
    let project = svc.create_project("exchange", T0).unwrap();
    svc.set_policy(&project, POLICY, T0).unwrap();
    svc.add_approver(&project, "alice", "Alice", T0).unwrap();
    (svc, project)
}

fn registration(device: &SoftAuthenticator, origin: &str, challenge_b64: &str) -> Registration {
    let challenge = B64.decode(challenge_b64).unwrap();
    let (authenticator_data, client_data_json) = device.register(RP_ID, origin, &challenge);
    Registration {
        authenticator_data: B64.encode(authenticator_data),
        client_data_json: B64.encode(client_data_json),
        public_key: B64.encode(device.public_key_der()),
        algorithm: ALG_ES256,
    }
}

fn enroll(svc: &Service, project: &str) -> SoftAuthenticator {
    let device = SoftAuthenticator::new();
    let token = svc.create_enrollment(project, "alice", T0).unwrap();
    let view = svc.enrollment_view(&token, T0).unwrap();
    assert_eq!(
        (view.rp_id.as_str(), view.approver_name.as_str()),
        (RP_ID, "Alice")
    );
    svc.complete_enrollment(&token, &registration(&device, ORIGIN, &view.challenge), T0)
        .unwrap();
    device
}

fn proof(device: &mut SoftAuthenticator, origin: &str, hash_b64: &str) -> Proof {
    let hash = B64.decode(hash_b64).unwrap();
    Proof::Passkey {
        credential_id: B64.encode(&device.credential_id),
        assertion: device.assert(RP_ID, origin, &hash),
    }
}

fn forbidden<T: std::fmt::Debug>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Forbidden(_)))
}

#[test]
fn passkey_approves_exactly_the_action_shown() {
    let (svc, project) = setup();
    let mut device = enroll(&svc, &project);
    let action =
        json!({ "type": "withdraw", "amount": "900", "asset": "USDT", "destination": "0xnew" });
    let ch = svc.create_challenge(&project, action, "k1", T0).unwrap();
    assert_eq!(ch.state, "pending");
    let view = svc.approver_view(&ch.id, T0).unwrap();

    let done = svc
        .submit(
            &ch.id,
            &proof(&mut device, ORIGIN, &view.binding_hash),
            false,
            T0,
        )
        .unwrap();
    assert_eq!(done.state, "approved");
    assert!(done.receipt.is_some());
    assert!(svc.audit_verify().is_ok());
}

#[test]
fn passkey_attacks_are_refused() {
    let (svc, project) = setup();
    let mut device = enroll(&svc, &project);
    let a = svc
        .create_challenge(
            &project,
            json!({ "type": "withdraw", "amount": "1" }),
            "k1",
            T0,
        )
        .unwrap();
    let b = svc
        .create_challenge(
            &project,
            json!({ "type": "withdraw", "amount": "999999" }),
            "k2",
            T0,
        )
        .unwrap();
    let view_a = svc.approver_view(&a.id, T0).unwrap();

    // A signature obtained for the small action, presented for the large one.
    assert!(forbidden(svc.submit(
        &b.id,
        &proof(&mut device, ORIGIN, &view_a.binding_hash),
        false,
        T0
    )));
    // A signature obtained on a look-alike site.
    assert!(forbidden(svc.submit(
        &a.id,
        &proof(
            &mut device,
            "https://2f.example.com.evil.io",
            &view_a.binding_hash
        ),
        false,
        T0
    )));
    // A refusal presented as an approval.
    assert!(forbidden(svc.submit(
        &a.id,
        &proof(&mut device, ORIGIN, &view_a.reject_hash),
        false,
        T0
    )));
    // Another authenticator claiming the enrolled credential id.
    let mut impostor = SoftAuthenticator::new();
    impostor.credential_id = device.credential_id.clone();
    assert!(forbidden(svc.submit(
        &a.id,
        &proof(&mut impostor, ORIGIN, &view_a.binding_hash),
        false,
        T0
    )));
    // A device that was never enrolled.
    let mut stranger = SoftAuthenticator::new();
    assert!(forbidden(svc.submit(
        &a.id,
        &proof(&mut stranger, ORIGIN, &view_a.binding_hash),
        false,
        T0
    )));
    // The device skipped PIN or biometrics.
    device.user_verified = false;
    assert!(forbidden(svc.submit(
        &a.id,
        &proof(&mut device, ORIGIN, &view_a.binding_hash),
        false,
        T0
    )));
    device.user_verified = true;

    assert_eq!(
        svc.get_challenge(&project, &a.id, T0).unwrap().state,
        "pending"
    );
    assert_eq!(
        svc.get_challenge(&project, &b.id, T0).unwrap().state,
        "pending"
    );

    // A real refusal works and is final.
    let rejected = svc
        .submit(
            &a.id,
            &proof(&mut device, ORIGIN, &view_a.reject_hash),
            true,
            T0,
        )
        .unwrap();
    assert_eq!(rejected.state, "rejected");
}

#[test]
fn a_cloned_authenticator_is_detected_by_its_counter() {
    let (svc, project) = setup();
    let mut device = enroll(&svc, &project);
    let approve = |device: &mut SoftAuthenticator, key: &str| {
        let ch = svc
            .create_challenge(
                &project,
                json!({ "type": "withdraw", "amount": key }),
                key,
                T0,
            )
            .unwrap();
        let view = svc.approver_view(&ch.id, T0).unwrap();
        svc.submit(
            &ch.id,
            &proof(device, ORIGIN, &view.binding_hash),
            false,
            T0,
        )
    };
    device.counter = 5;
    assert!(approve(&mut device, "1").is_ok());
    // The clone still has the old counter value.
    device.counter = 5;
    assert!(forbidden(approve(&mut device, "2")));
    device.counter = 6;
    assert!(approve(&mut device, "3").is_ok());
}

#[test]
fn enrollment_links_are_single_use_and_expire() {
    let (svc, project) = setup();
    let device = SoftAuthenticator::new();
    let token = svc.create_enrollment(&project, "alice", T0).unwrap();
    let view = svc.enrollment_view(&token, T0).unwrap();

    // Wrong challenge, wrong origin, wrong algorithm.
    let other = B64.encode([9u8; 32]);
    assert!(forbidden(svc.complete_enrollment(
        &token,
        &registration(&device, ORIGIN, &other),
        T0
    )));
    assert!(forbidden(svc.complete_enrollment(
        &token,
        &registration(&device, "https://evil.io", &view.challenge),
        T0
    )));
    let mut wrong_alg = registration(&device, ORIGIN, &view.challenge);
    wrong_alg.algorithm = -257;
    assert!(forbidden(svc.complete_enrollment(&token, &wrong_alg, T0)));

    let good = registration(&device, ORIGIN, &view.challenge);
    assert!(svc.complete_enrollment(&token, &good, T0).is_ok());
    // Used links stop working, for viewing and for enrolling.
    assert!(matches!(
        svc.enrollment_view(&token, T0),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        svc.complete_enrollment(&token, &good, T0),
        Err(Error::NotFound)
    ));

    let late = svc.create_enrollment(&project, "alice", T0).unwrap();
    assert!(matches!(
        svc.enrollment_view(&late, T0 + ENROLLMENT_TTL + 1),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        svc.enrollment_view("guess", T0),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        svc.create_enrollment(&project, "ghost", T0),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_device_key_does_not_satisfy_a_passkey_only_rule() {
    let (svc, project) = setup();
    let key = ServerKey::generate();
    let cred = svc
        .add_credential(
            &project,
            "alice",
            twof_core::ApproverKind::Ed25519,
            &key.public_hex(),
            T0,
        )
        .unwrap();
    let ch = svc
        .create_challenge(&project, json!({ "type": "withdraw" }), "k1", T0)
        .unwrap();
    let hash = svc.approver_view(&ch.id, T0).unwrap().binding.hash();
    assert!(forbidden(svc.submit_approval(
        &ch.id,
        &cred,
        &B64.encode(key.sign(&hash)),
        false,
        T0
    )));
}
