//! An attacker who can write to the database file but does not hold the
//! signing key. Every way of granting themselves power must fail, and the
//! audit check must notice the attempt.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use twof_core::keys::ServerKey;
use twof_core::ApproverKind;
use twof_server::{Config, Error, Service};

const T0: u64 = 1_800_000_000;
const POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "small", "when": { "type": ["withdraw"], "amount_max": "10" }, "then": { "decision": "allow" } },
    { "name": "ask two", "when": {}, "then": { "decision": "require", "requirements": [ { "count": 2 } ] } } ] }"#;
const ALLOW_ALL: &str =
    r#"{"version":1,"lists":{},"rules":[{"name":"x","when":{},"then":{"decision":"allow"}}]}"#;

struct World {
    path: PathBuf,
    svc: Service,
    raw: rusqlite::Connection,
    project: String,
    alice: (ServerKey, String),
    bob: (ServerKey, String),
}

impl Drop for World {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn world(name: &str) -> World {
    let mut path = std::env::temp_dir();
    path.push(format!("twof-tamper-{name}-{}.db", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let svc = Service::open(&path, ServerKey::generate(), Config::default()).unwrap();
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
    let (alice, bob) = (enroll("alice"), enroll("bob"));
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    World {
        path,
        svc,
        raw,
        project,
        alice,
        bob,
    }
}

fn big() -> Value {
    json!({ "type": "withdraw", "amount": "999999", "asset": "USDT", "destination": "0xevil" })
}

fn sign(w: &World, key: &ServerKey, id: &str) -> String {
    twof_core::b64(&key.sign(&w.svc.approver_view(id, T0).unwrap().binding.hash()))
}

fn audit_broken(w: &World) -> bool {
    matches!(w.svc.audit_verify(), Err(Error::Conflict(_)))
}

#[test]
fn inserting_an_approver_credential_gives_no_power() {
    let w = world("credential");
    let mallory = ServerKey::generate();
    // The attacker copies everything an honest row has, including a seal
    // lifted from alice's row.
    w.raw
        .execute(
            "INSERT INTO approvers (project, id, name, created_at) VALUES (?, 'mallory', 'M', 0)",
            [&w.project],
        )
        .unwrap();
    w.raw
        .execute(
            "INSERT INTO credentials (id, project, approver, kind, public_key, seal, created_at) \
         SELECT 'cr_evil', project, 'mallory', kind, ?, seal, 0 FROM credentials WHERE id = ?",
            [&mallory.public_hex(), &w.alice.1],
        )
        .unwrap();

    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let sig = sign(&w, &mallory, &ch.id);
    assert!(matches!(
        w.svc.submit_approval(&ch.id, "cr_evil", &sig, false, T0),
        Err(Error::Forbidden(_))
    ));
    assert!(audit_broken(&w), "the extra credential is reported");
}

#[test]
fn swapping_the_public_key_of_a_real_approver_gives_no_power() {
    let w = world("swap");
    let mallory = ServerKey::generate();
    w.raw
        .execute(
            "UPDATE credentials SET public_key = ? WHERE id = ?",
            [&mallory.public_hex(), &w.alice.1],
        )
        .unwrap();
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let sig = sign(&w, &mallory, &ch.id);
    assert!(matches!(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, T0),
        Err(Error::Forbidden(_))
    ));
    assert!(audit_broken(&w));
}

#[test]
fn rewriting_the_policy_fails_closed() {
    let w = world("policy");
    assert_eq!(
        w.svc
            .create_challenge(
                &w.project,
                json!({ "type": "withdraw", "amount": "5" }),
                "k0",
                T0
            )
            .unwrap()
            .state,
        "allowed"
    );

    w.raw
        .execute(
            "UPDATE projects SET policy = ? WHERE id = ?",
            [ALLOW_ALL, w.project.as_str()],
        )
        .unwrap();
    // Not "allowed" as the attacker wanted, and not even "pending": denied.
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    assert_eq!((ch.state.as_str(), ch.receipt), ("denied", None));

    // Moving a valid seal from another project does not help either.
    let other = w.svc.create_project("other", T0).unwrap();
    w.svc.set_policy(&other, ALLOW_ALL, T0).unwrap();
    w.raw.execute(
        "UPDATE projects SET policy_seal = (SELECT policy_seal FROM projects WHERE id = ?) WHERE id = ?",
        [other.as_str(), w.project.as_str()],
    ).unwrap();
    assert_eq!(
        w.svc
            .create_challenge(&w.project, big(), "k2", T0)
            .unwrap()
            .state,
        "denied"
    );
}

#[test]
fn inserting_an_api_key_gives_no_access() {
    let w = world("apikey");
    let real = w.svc.create_api_key(&w.project, "bot", T0).unwrap();
    let forged = "2f_attacker-chosen-value";
    let hash = hex::encode(Sha256::digest(forged.as_bytes()));
    w.raw
        .execute(
            "INSERT INTO api_keys (id, project, hash, label, seal, created_at) \
         SELECT 'ak_evil', project, ?, 'x', seal, 0 FROM api_keys LIMIT 1",
            [&hash],
        )
        .unwrap();
    assert!(matches!(
        w.svc.authenticate(forged),
        Err(Error::Unauthorized)
    ));
    assert_eq!(w.svc.authenticate(&real).unwrap(), w.project);
    assert!(audit_broken(&w));
}

#[test]
fn undoing_a_revocation_does_not_bring_a_credential_back() {
    let w = world("unrevoke");
    w.svc.revoke_credential(&w.project, &w.alice.1, T0).unwrap();
    w.raw
        .execute(
            "UPDATE credentials SET revoked_at = NULL WHERE id = ?",
            [&w.alice.1],
        )
        .unwrap();
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let sig = sign(&w, &w.alice.0, &ch.id);
    assert!(matches!(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, T0),
        Err(Error::Forbidden(_))
    ));
    assert!(audit_broken(&w));
}

#[test]
fn audit_entries_cannot_be_appended_without_the_key() {
    let w = world("append");
    assert!(w.svc.audit_verify().is_ok());
    // A correctly chained entry, with the signature copied from the last one.
    let (seq, hash, sig): (i64, String, String) = w
        .raw
        .query_row(
            "SELECT seq, hash, sig FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let forged = twof_core::audit::next_entry(
        Some((seq as u64, &hash)),
        T0,
        "credential.added",
        json!({ "credential": "cr_evil" }),
    )
    .unwrap();
    w.raw
        .execute(
            "INSERT INTO audit (seq, ts, kind, data, prev, hash, sig) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                forged.seq as i64,
                forged.ts as i64,
                forged.kind,
                forged.data.to_string(),
                forged.prev,
                forged.hash,
                sig
            ],
        )
        .unwrap();
    assert!(
        twof_core::audit::verify_chain(&w.svc.audit_entries().unwrap()).is_ok(),
        "the chain alone is fooled"
    );
    assert!(audit_broken(&w), "the signature check is not");
}

#[test]
fn an_approval_stops_counting_when_its_approver_is_removed() {
    let w = world("quorum");
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let after_alice = w
        .svc
        .submit_approval(&ch.id, &w.alice.1, &sign(&w, &w.alice.0, &ch.id), false, T0)
        .unwrap();
    assert_eq!(
        (after_alice.state.as_str(), after_alice.approvals.len()),
        ("pending", 1)
    );

    // Alice is found to be compromised before the second person approves.
    w.svc.disable_approver(&w.project, "alice", T0).unwrap();
    let after_bob = w
        .svc
        .submit_approval(&ch.id, &w.bob.1, &sign(&w, &w.bob.0, &ch.id), false, T0)
        .unwrap();
    assert_eq!(
        (after_bob.state.as_str(), after_bob.approvals.len()),
        ("pending", 1)
    );
    assert!(after_bob.receipt.is_none());

    // She cannot approve anything new, and cannot be given a new credential.
    assert!(matches!(
        w.svc
            .submit_approval(&ch.id, &w.alice.1, &sign(&w, &w.alice.0, &ch.id), false, T0),
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        w.svc.add_credential(
            &w.project,
            "alice",
            ApproverKind::Ed25519,
            &ServerKey::generate().public_hex(),
            T0
        ),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        w.svc.create_enrollment(&w.project, "alice", T0),
        Err(Error::NotFound)
    ));
    assert!(w.svc.audit_verify().is_ok());
}

#[test]
fn concurrent_writers_keep_every_guarantee() {
    let mut w = world("concurrent");
    w.svc.set_policy(&w.project, r#"{"version":1,"rules":[{"name":"cap","when":{"asset":["USDT"],"velocity":{"window_secs":3600,"max_total":"100"}},"then":{"decision":"allow"}},{"name":"ask","when":{},"then":{"decision":"require","requirements":[{"count":1}]}}]}"#, T0).unwrap();
    let project = w.project.clone();
    let svc = Arc::new(std::mem::replace(
        &mut w.svc,
        Service::open_in_memory(ServerKey::generate(), Config::default()).unwrap(),
    ));

    // 16 threads race to spend a budget that fits exactly 10 transfers of 10.
    let handles: Vec<_> = (0..16).map(|t| {
        let (svc, project) = (svc.clone(), project.clone());
        std::thread::spawn(move || {
            (0..5).filter(|i| {
                let action = json!({ "type": "withdraw", "amount": "10", "asset": "USDT", "destination": "0xaaa" });
                svc.create_challenge(&project, action, &format!("v-{t}-{i}"), T0).unwrap().state == "allowed"
            }).count()
        })
    }).collect();
    let allowed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(allowed, 10, "the velocity cap holds under concurrency");

    // 16 threads race to consume the same receipt.
    let token = svc
        .create_challenge(
            &project,
            json!({ "type": "withdraw", "amount": "0", "asset": "USDT" }),
            "one",
            T0 + 7200,
        )
        .unwrap()
        .receipt
        .unwrap();
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let (svc, project, token) = (svc.clone(), project.clone(), token.clone());
            std::thread::spawn(move || svc.consume_receipt(&project, &token, T0 + 7200).is_ok())
        })
        .collect();
    let consumed = handles
        .into_iter()
        .filter(|_| true)
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(consumed, 1, "a receipt is consumed exactly once");

    // The same idempotency key from many threads yields one challenge.
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let (svc, project) = (svc.clone(), project.clone());
            std::thread::spawn(move || {
                svc.create_challenge(&project, json!({ "type": "x" }), "same", T0)
                    .unwrap()
                    .id
            })
        })
        .collect();
    let ids: std::collections::BTreeSet<String> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(ids.len(), 1);
    assert!(
        svc.audit_verify().is_ok(),
        "the audit chain is intact after concurrent writes"
    );
}
