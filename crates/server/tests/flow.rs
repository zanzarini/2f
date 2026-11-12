//! End to end behaviour of the service, including the attacks listed in
//! docs/THREAT_MODEL.md. Each "must fail" case there has a test here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use twof_core::keys::ServerKey;
use twof_core::receipt;
use twof_core::{Action, ApproverKind, Binding};
use twof_server::{Config, Error, Service};

const T0: u64 = 1_800_000_000;

const POLICY: &str = r#"{
    "version": 1,
    "lists": { "treasury": ["0xaaa"] },
    "rules": [
        { "name": "small to treasury",
          "when": { "type": ["withdraw"], "asset": ["USDT"], "amount_max": "100",
                    "destination_in": ["treasury"],
                    "velocity": { "window_secs": 3600, "max_total": "150" } },
          "then": { "decision": "allow" } },
        { "name": "big needs two people",
          "when": { "type": ["withdraw"], "amount_min": "10000" },
          "then": { "decision": "require", "requirements": [ { "count": 2 } ] } },
        { "name": "withdraw needs one person",
          "when": { "type": ["withdraw"] },
          "then": { "decision": "require", "requirements": [ { "count": 1 } ] } }
    ]
}"#;

struct World {
    svc: Service,
    project: String,
    alice: (ServerKey, String),
    bob: (ServerKey, String),
}

fn world() -> World {
    let svc = Service::open_in_memory(ServerKey::generate(), Config::default()).unwrap();
    let project = svc.create_project("exchange", T0).unwrap();
    svc.set_policy(&project, POLICY, T0).unwrap();
    let enroll = |name: &str| {
        let key = ServerKey::generate();
        svc.add_approver(&project, name, name, T0).unwrap();
        let cred = svc
            .add_credential(&project, name, ApproverKind::Ed25519, &key.public_hex(), T0)
            .unwrap();
        (key, cred)
    };
    let alice = enroll("alice");
    let bob = enroll("bob");
    World {
        svc,
        project,
        alice,
        bob,
    }
}

fn withdraw(amount: &str, destination: &str) -> Value {
    json!({ "type": "withdraw", "amount": amount, "asset": "USDT", "destination": destination })
}

fn binding(w: &World, id: &str) -> Binding {
    w.svc.approver_view(id, T0).unwrap().binding
}

fn sign(key: &ServerKey, hash: [u8; 32]) -> String {
    B64.encode(key.sign(&hash))
}

fn verify(
    w: &World,
    token: &str,
    action: &Value,
    now: u64,
) -> Result<twof_core::ReceiptPayload, receipt::ReceiptError> {
    let key = w.svc.key();
    let lookup = |kid: &str| (kid == key.kid()).then(|| key.public());
    receipt::verify(
        token,
        &lookup,
        &Action::from_value(action.clone()).unwrap(),
        now,
    )
}

fn is_forbidden<T: std::fmt::Debug>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Forbidden(_)))
}

#[test]
fn small_known_transfer_passes_alone_and_receipt_is_single_use() {
    let w = world();
    let action = withdraw("50", "0xaaa");
    let ch = w
        .svc
        .create_challenge(&w.project, action.clone(), "k1", T0)
        .unwrap();
    assert_eq!(ch.state, "allowed");
    assert_eq!(ch.rule.as_deref(), Some("small to treasury"));
    let token = ch.receipt.unwrap();
    assert!(verify(&w, &token, &action, T0).is_ok());

    assert!(w.svc.consume_receipt(&w.project, &token, T0 + 1).is_ok());
    assert!(matches!(
        w.svc.consume_receipt(&w.project, &token, T0 + 2),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn receipt_does_not_cover_an_altered_action() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xaaa"), "k1", T0)
        .unwrap();
    let token = ch.receipt.unwrap();
    assert_eq!(
        verify(&w, &token, &withdraw("5000", "0xaaa"), T0),
        Err(receipt::ReceiptError::ActionMismatch)
    );
    assert_eq!(
        verify(&w, &token, &withdraw("50", "0xevil"), T0),
        Err(receipt::ReceiptError::ActionMismatch)
    );
}

#[test]
fn expired_receipts_are_refused() {
    let w = world();
    let action = withdraw("50", "0xaaa");
    let token = w
        .svc
        .create_challenge(&w.project, action.clone(), "k1", T0)
        .unwrap()
        .receipt
        .unwrap();
    let late = T0 + w.svc.config.receipt_ttl + 1;
    assert_eq!(
        verify(&w, &token, &action, late),
        Err(receipt::ReceiptError::Expired)
    );
    assert!(matches!(
        w.svc.consume_receipt(&w.project, &token, late),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn velocity_limit_stops_many_small_transfers() {
    let w = world();
    let states: Vec<String> = (0..3)
        .map(|i| {
            w.svc
                .create_challenge(
                    &w.project,
                    withdraw("60", "0xaaa"),
                    &format!("k{i}"),
                    T0 + i,
                )
                .unwrap()
                .state
        })
        .collect();
    // 60 + 60 = 120 fits under 150; the third would make 180.
    assert_eq!(states, ["allowed", "allowed", "pending"]);
    // After the window the allowance is back.
    let later = w
        .svc
        .create_challenge(&w.project, withdraw("60", "0xaaa"), "k9", T0 + 3700)
        .unwrap();
    assert_eq!(later.state, "allowed");
}

#[test]
fn unknown_destination_needs_a_human_and_approval_issues_a_receipt() {
    let w = world();
    let action = withdraw("50", "0xnew");
    let ch = w
        .svc
        .create_challenge(&w.project, action.clone(), "k1", T0)
        .unwrap();
    assert_eq!(ch.state, "pending");
    assert!(ch.receipt.is_none());
    assert!(ch.approve_url.unwrap().ends_with(&ch.id));

    let b = binding(&w, &ch.id);
    let done = w
        .svc
        .submit_approval(
            &ch.id,
            &w.alice.1,
            &sign(&w.alice.0, b.hash()),
            false,
            T0 + 5,
        )
        .unwrap();
    assert_eq!(done.state, "approved");
    let token = done.receipt.unwrap();
    let payload = verify(&w, &token, &action, T0 + 6).unwrap();

    // The client can check alice's signature itself, without trusting the server.
    let pinned = BTreeMap::from([("alice".to_string(), w.alice.0.public())]);
    assert_eq!(payload.pinned_approvals(&pinned).len(), 1);
    let wrong_pin = BTreeMap::from([("alice".to_string(), w.bob.0.public())]);
    assert!(payload.pinned_approvals(&wrong_pin).is_empty());
}

#[test]
fn forged_approvals_are_refused() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let b = binding(&w, &ch.id);
    let outsider = ServerKey::generate();

    // Signature by a key that was never enrolled, presented under alice's credential.
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &w.alice.1,
        &sign(&outsider, b.hash()),
        false,
        T0
    )));
    // Bob's valid signature presented under alice's credential.
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &w.alice.1,
        &sign(&w.bob.0, b.hash()),
        false,
        T0
    )));
    // A credential id that does not exist.
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        "cr_nope",
        &sign(&w.alice.0, b.hash()),
        false,
        T0
    )));
    // Garbage in place of a signature.
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &w.alice.1,
        "not base64 !!",
        false,
        T0
    )));
    assert!(is_forbidden(
        w.svc.submit_approval(&ch.id, &w.alice.1, "", false, T0)
    ));

    assert_eq!(
        w.svc.get_challenge(&w.project, &ch.id, T0).unwrap().state,
        "pending"
    );
}

#[test]
fn an_approval_cannot_be_replayed_on_another_challenge() {
    let w = world();
    let small = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let big = w
        .svc
        .create_challenge(&w.project, withdraw("9000", "0xevil"), "k2", T0)
        .unwrap();
    let sig_for_small = sign(&w.alice.0, binding(&w, &small.id).hash());
    assert!(is_forbidden(w.svc.submit_approval(
        &big.id,
        &w.alice.1,
        &sig_for_small,
        false,
        T0
    )));
}

#[test]
fn a_refusal_cannot_be_replayed_as_an_approval() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let b = binding(&w, &ch.id);
    let reject_sig = sign(&w.alice.0, b.reject_hash());
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &w.alice.1,
        &reject_sig,
        false,
        T0
    )));
    let approve_sig = sign(&w.alice.0, b.hash());
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &w.alice.1,
        &approve_sig,
        true,
        T0
    )));

    let rejected = w
        .svc
        .submit_approval(&ch.id, &w.alice.1, &reject_sig, true, T0)
        .unwrap();
    assert_eq!(rejected.state, "rejected");
    assert!(rejected.receipt.is_none());
    // Once refused, a later approval changes nothing.
    assert!(matches!(
        w.svc
            .submit_approval(&ch.id, &w.bob.1, &sign(&w.bob.0, b.hash()), false, T0),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn two_person_rule_needs_two_different_people() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50000", "0xnew"), "k1", T0)
        .unwrap();
    assert_eq!(ch.rule.as_deref(), Some("big needs two people"));
    let b = binding(&w, &ch.id);

    // Alice enrolls a second device and signs with both: still one person.
    let second_device = ServerKey::generate();
    let second_cred = w
        .svc
        .add_credential(
            &w.project,
            "alice",
            ApproverKind::Ed25519,
            &second_device.public_hex(),
            T0,
        )
        .unwrap();
    let s = w
        .svc
        .submit_approval(&ch.id, &w.alice.1, &sign(&w.alice.0, b.hash()), false, T0)
        .unwrap();
    assert_eq!(s.state, "pending");
    let s = w
        .svc
        .submit_approval(
            &ch.id,
            &second_cred,
            &sign(&second_device, b.hash()),
            false,
            T0,
        )
        .unwrap();
    assert_eq!(s.state, "pending");
    // Submitting the same approval again changes nothing.
    let s = w
        .svc
        .submit_approval(&ch.id, &w.alice.1, &sign(&w.alice.0, b.hash()), false, T0)
        .unwrap();
    assert_eq!(s.state, "pending");

    let s = w
        .svc
        .submit_approval(&ch.id, &w.bob.1, &sign(&w.bob.0, b.hash()), false, T0)
        .unwrap();
    assert_eq!(s.state, "approved");
    assert!(s.receipt.is_some());
}

#[test]
fn expired_challenges_cannot_be_approved() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let sig = sign(&w.alice.0, binding(&w, &ch.id).hash());
    let late = T0 + w.svc.config.challenge_ttl + 1;
    assert!(matches!(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, late),
        Err(Error::Conflict(_))
    ));
    assert_eq!(
        w.svc.get_challenge(&w.project, &ch.id, late).unwrap().state,
        "expired"
    );
}

#[test]
fn revoked_credentials_stop_working() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let sig = sign(&w.alice.0, binding(&w, &ch.id).hash());
    w.svc.revoke_credential(&w.project, &w.alice.1, T0).unwrap();
    assert!(is_forbidden(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, T0)
    ));
}

#[test]
fn no_matching_rule_and_unconfigured_projects_deny() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, json!({ "type": "trade" }), "k1", T0)
        .unwrap();
    assert_eq!(
        (ch.state.as_str(), ch.rule, ch.receipt),
        ("denied", None, None)
    );

    let fresh = w.svc.create_project("new", T0).unwrap();
    let ch = w
        .svc
        .create_challenge(&fresh, withdraw("1", "0xaaa"), "k1", T0)
        .unwrap();
    assert_eq!(ch.state, "denied");
}

#[test]
fn idempotency_key_returns_the_same_challenge_or_conflicts() {
    let w = world();
    let first = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    let again = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0 + 1)
        .unwrap();
    assert_eq!(first.id, again.id);
    assert!(matches!(
        w.svc
            .create_challenge(&w.project, withdraw("51", "0xnew"), "k1", T0),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn projects_are_isolated() {
    let w = world();
    let other = w.svc.create_project("other", T0).unwrap();
    w.svc.set_policy(&other, POLICY, T0).unwrap();
    let mallory = ServerKey::generate();
    w.svc
        .add_approver(&other, "mallory", "Mallory", T0)
        .unwrap();
    let mallory_cred = w
        .svc
        .add_credential(
            &other,
            "mallory",
            ApproverKind::Ed25519,
            &mallory.public_hex(),
            T0,
        )
        .unwrap();

    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xnew"), "k1", T0)
        .unwrap();
    // An approver of another project cannot approve here.
    let sig = sign(&mallory, binding(&w, &ch.id).hash());
    assert!(is_forbidden(w.svc.submit_approval(
        &ch.id,
        &mallory_cred,
        &sig,
        false,
        T0
    )));
    // Another project's API key cannot read the challenge or use its receipt.
    assert!(matches!(
        w.svc.get_challenge(&other, &ch.id, T0),
        Err(Error::NotFound)
    ));
    let token = w
        .svc
        .create_challenge(&w.project, withdraw("50", "0xaaa"), "k2", T0)
        .unwrap()
        .receipt
        .unwrap();
    assert!(matches!(
        w.svc.consume_receipt(&other, &token, T0),
        Err(Error::NotFound)
    ));

    // API keys resolve to their own project, and stop when revoked.
    let key = w.svc.create_api_key(&other, "bot", T0).unwrap();
    assert_eq!(w.svc.authenticate(&key).unwrap(), other);
    assert!(matches!(
        w.svc.authenticate("2f_guess"),
        Err(Error::Unauthorized)
    ));
    w.svc.revoke_api_keys(&other, T0).unwrap();
    assert!(matches!(w.svc.authenticate(&key), Err(Error::Unauthorized)));
}

#[test]
fn invalid_input_is_rejected() {
    let w = world();
    for bad in [
        json!({ "type": "withdraw", "amount": 50 }),
        json!({ "type": "withdraw", "amount": "-50" }),
        json!({ "type": "withdraw", "surprise": true }),
        json!({ "amount": "50" }),
        json!("withdraw"),
    ] {
        assert!(matches!(
            w.svc.create_challenge(&w.project, bad, "k", T0),
            Err(Error::Invalid(_))
        ));
    }
    assert!(matches!(w.svc.set_policy(&w.project, r#"{"version":1,"rules":[{"name":"x","when":{"amout_max":"1"},"then":{"decision":"allow"}}]}"#, T0), Err(Error::Invalid(_))));
    assert!(matches!(
        w.svc
            .add_credential(&w.project, "alice", ApproverKind::Ed25519, "zz", T0),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        w.svc.add_credential(
            &w.project,
            "ghost",
            ApproverKind::Ed25519,
            &ServerKey::generate().public_hex(),
            T0
        ),
        Err(Error::NotFound)
    ));
}

fn temp_db(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-test-{name}-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

#[test]
fn editing_the_database_is_detected_by_the_audit_log() {
    let path = temp_db("audit");
    let svc = Service::open(&path, ServerKey::generate(), Config::default()).unwrap();
    let project = svc.create_project("exchange", T0).unwrap();
    svc.set_policy(&project, POLICY, T0).unwrap();
    svc.create_challenge(&project, withdraw("50", "0xaaa"), "k1", T0)
        .unwrap();
    svc.create_challenge(&project, withdraw("70", "0xnew"), "k2", T0)
        .unwrap();
    let head = svc.audit_verify().unwrap().unwrap();
    assert!(head.0 >= 5);
    let checkpoint = svc.checkpoint(T0).unwrap().unwrap();
    assert_eq!(checkpoint.seq, head.0);
    assert!(svc.audit_verify().is_ok());

    let raw = rusqlite::Connection::open(&path).unwrap();
    let tamper = |sql: &str| raw.execute(sql, []).unwrap();
    let broken = |svc: &Service| matches!(svc.audit_verify(), Err(Error::Conflict(_)));

    // Rewrite history: pretend the 70 went to another address.
    let original: String = raw
        .query_row("SELECT data FROM audit WHERE seq = 5", [], |r| r.get(0))
        .unwrap();
    assert!(original.contains("0xnew"));
    raw.execute(
        "UPDATE audit SET data = ? WHERE seq = 5",
        [original.replace("0xnew", "0xaaa")],
    )
    .unwrap();
    assert!(broken(&svc));
    raw.execute("UPDATE audit SET data = ? WHERE seq = 5", [&original])
        .unwrap();
    assert!(svc.audit_verify().is_ok());

    // Remove the newest entries: the chain alone is consistent, the checkpoint is not.
    tamper("CREATE TABLE saved AS SELECT * FROM audit");
    tamper(&format!("DELETE FROM audit WHERE seq = {}", head.0));
    assert!(broken(&svc));
    tamper("DELETE FROM audit");
    tamper("INSERT INTO audit SELECT * FROM saved");
    assert!(svc.audit_verify().is_ok());

    // Remove one from the middle.
    tamper("DELETE FROM audit WHERE seq = 2");
    assert!(broken(&svc));
}

#[test]
fn a_leaked_database_cannot_issue_receipts_or_call_the_api() {
    let path = temp_db("leak");
    let real = Service::open(&path, ServerKey::generate(), Config::default()).unwrap();
    let project = real.create_project("exchange", T0).unwrap();
    real.set_policy(&project, POLICY, T0).unwrap();
    let api_key = real.create_api_key(&project, "bot", T0).unwrap();
    let action = withdraw("50", "0xaaa");
    real.create_challenge(&project, action.clone(), "k1", T0)
        .unwrap();

    // The attacker has the whole file but not the signing key.
    let dump = std::fs::read(&path).unwrap();
    let wal = std::fs::read(format!("{}-wal", path.display())).unwrap_or_default();
    let contains = |needle: &[u8]| {
        [&dump, &wal]
            .iter()
            .any(|hay| hay.windows(needle.len()).any(|w| w == needle))
    };
    assert!(
        !contains(api_key.as_bytes()),
        "API key must not be stored in clear"
    );
    assert!(
        !contains(real.key().seed_hex().as_bytes()),
        "signing key must not be in the database"
    );

    let attacker = Service::open(&path, ServerKey::generate(), Config::default()).unwrap();
    // With their own key the sealed policy and API key are not recognised.
    assert!(matches!(
        attacker.authenticate(&api_key),
        Err(Error::Unauthorized)
    ));
    let refused = attacker
        .create_challenge(&project, action.clone(), "k2", T0)
        .unwrap();
    assert_eq!(refused.state, "denied");
    // Even after sealing a policy of their own, what they sign is not ours.
    attacker.set_policy(&project, POLICY, T0).unwrap();
    let forged = attacker
        .create_challenge(&project, action.clone(), "k3", T0)
        .unwrap()
        .receipt
        .unwrap();
    let real_key = real.key();
    let lookup = |kid: &str| (kid == real_key.kid()).then(|| real_key.public());
    let parsed = Action::from_value(action).unwrap();
    assert_eq!(
        receipt::verify(&forged, &lookup, &parsed, T0),
        Err(receipt::ReceiptError::UnknownKey)
    );
    assert!(real.consume_receipt(&project, &forged, T0).is_err());
}
