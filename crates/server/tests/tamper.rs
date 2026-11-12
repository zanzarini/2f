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
    { "name": "small", "when": { "type": ["withdraw"], "asset": ["USDT"], "amount_max": "10" }, "then": { "decision": "allow" } },
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
                json!({ "type": "withdraw", "amount": "5", "asset": "USDT" }),
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
                // Past the cap the rest wait for a person, and past the limit of
                // waiting requests they are turned away; neither is "allowed".
                svc.create_challenge(&project, action, &format!("v-{t}-{i}"), T0).is_ok_and(|c| c.state == "allowed")
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
                // Later in time, when the requests left waiting above have run out.
                svc.create_challenge(&project, json!({ "type": "x" }), "same", T0 + 7200)
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

#[test]
fn a_planted_approval_row_does_not_count_toward_the_quorum() {
    let w = world("fake-approval");
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    // The attacker controls bob, and writes a row saying alice approved too.
    w.raw
        .execute(
            "INSERT INTO approvals (challenge, approver, credential, kind, sig, created_at) \
         VALUES (?, 'alice', ?, 'ed25519', ?, 0)",
            rusqlite::params![ch.id, w.alice.1, twof_core::b64(&[7u8; 64])],
        )
        .unwrap();
    let after = w
        .svc
        .submit_approval(&ch.id, &w.bob.1, &sign(&w, &w.bob.0, &ch.id), false, T0)
        .unwrap();
    assert_eq!(
        (after.state.as_str(), after.approvals.len()),
        ("pending", 1)
    );
    assert!(after.receipt.is_none());

    // Alice's real signature on another challenge, moved here, is no better.
    let other = w
        .svc
        .create_challenge(&w.project, json!({ "type": "x" }), "k2", T0)
        .unwrap();
    w.raw
        .execute(
            "UPDATE approvals SET sig = ? WHERE challenge = ? AND approver = 'alice'",
            rusqlite::params![sign(&w, &w.alice.0, &other.id), ch.id],
        )
        .unwrap();
    assert_eq!(
        w.svc
            .get_challenge(&w.project, &ch.id, T0)
            .unwrap()
            .approvals
            .len(),
        1
    );
}

#[test]
fn weakening_or_reviving_a_challenge_is_refused() {
    let w = world("challenge-row");
    let sql = |text: &str, id: &str| w.raw.execute(text, [id]).unwrap();
    let tampered = |r: Result<twof_server::service::ChallengeView, Error>| matches!(r, Err(Error::Conflict(m)) if m.contains("integrity"));

    // Two people required: rewrite the stored requirement to one.
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    sql(
        r#"UPDATE challenges SET requirements = '[{"count":1,"min_strength":"strong"}]' WHERE id = ?"#,
        &ch.id,
    );
    assert!(tampered(w.svc.submit_approval(
        &ch.id,
        &w.bob.1,
        &twof_core::b64(&[1u8; 64]),
        false,
        T0
    )));
    assert!(tampered(w.svc.get_challenge(&w.project, &ch.id, T0)));
    assert!(w.svc.approver_view(&ch.id, T0).is_err());

    // A refused challenge set back to pending.
    let ch = w.svc.create_challenge(&w.project, big(), "k2", T0).unwrap();
    let reject = twof_core::b64(
        &w.alice.0.sign(
            &w.svc
                .approver_view(&ch.id, T0)
                .unwrap()
                .binding
                .reject_hash(),
        ),
    );
    assert_eq!(
        w.svc
            .submit_approval(&ch.id, &w.alice.1, &reject, true, T0)
            .unwrap()
            .state,
        "rejected"
    );
    sql(
        "UPDATE challenges SET state = 'pending' WHERE id = ?",
        &ch.id,
    );
    assert!(tampered(w.svc.get_challenge(&w.project, &ch.id, T0)));

    // A denied one promoted to allowed.
    let ch = w
        .svc
        .create_challenge(
            &w.project,
            json!({ "type": "withdraw", "amount": "5", "asset": "USDT" }),
            "k3",
            T0,
        )
        .unwrap();
    assert_eq!(ch.state, "allowed");
    let denied = w.svc.create_challenge(
        &w.project,
        json!({ "type": "withdraw", "amount": "5", "asset": "SCAM" }),
        "k4",
        T0,
    );
    let denied = denied.unwrap();
    sql(
        "UPDATE challenges SET state = 'allowed' WHERE id = ?",
        &denied.id,
    );
    assert!(tampered(w.svc.get_challenge(&w.project, &denied.id, T0)));

    // The deadline pushed forward.
    let ch = w.svc.create_challenge(&w.project, big(), "k5", T0).unwrap();
    sql(
        "UPDATE challenges SET expires_at = expires_at + 999999 WHERE id = ?",
        &ch.id,
    );
    assert!(tampered(w.svc.get_challenge(&w.project, &ch.id, T0)));
    assert!(
        audit_broken(&w),
        "the states in the table no longer match the log"
    );
}

#[test]
fn the_approver_is_never_shown_a_different_action_than_the_one_signed() {
    let w = world("display");
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    // Keep the hash of the dangerous action, show a harmless one.
    w.raw.execute(
        r#"UPDATE challenges SET action = '{"amount":"1","asset":"USDT","destination":"0xfriend","type":"withdraw"}' WHERE id = ?"#,
        [&ch.id],
    ).unwrap();
    assert!(matches!(
        w.svc.approver_view(&ch.id, T0),
        Err(Error::Conflict(_))
    ));
    let sig = twof_core::b64(&[0u8; 64]);
    assert!(matches!(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, T0),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn a_planted_enrollment_link_does_not_enroll_a_device() {
    use twof_core::passkey::testing::SoftAuthenticator;
    use twof_core::passkey::ALG_ES256;
    let w = world("enrollment");
    // The attacker invents a link for alice, copying the seal of a real one.
    let real = w.svc.create_enrollment(&w.project, "alice", T0).unwrap();
    let token = "attacker-chosen-token";
    w.raw
        .execute(
            "INSERT INTO enrollments (token_hash, project, approver, challenge, expires_at, seal) \
         SELECT ?, project, approver, challenge, expires_at, seal FROM enrollments",
            [hex::encode(Sha256::digest(token.as_bytes()))],
        )
        .unwrap();
    assert!(matches!(
        w.svc.enrollment_view(token, T0),
        Err(Error::NotFound)
    ));
    let view = w.svc.enrollment_view(&real, T0).unwrap();
    let device = SoftAuthenticator::new();
    let challenge = twof_core::unb64(&view.challenge).unwrap();
    let (authenticator_data, client_data_json) =
        device.register("localhost", "http://localhost:8722", &challenge);
    let registration = twof_server::Registration {
        authenticator_data: twof_core::b64(&authenticator_data),
        client_data_json: twof_core::b64(&client_data_json),
        public_key: twof_core::b64(&device.public_key_der()),
        algorithm: ALG_ES256,
    };
    assert!(matches!(
        w.svc.complete_enrollment(token, &registration, T0),
        Err(Error::NotFound)
    ));
    // Stretching the life of a real link is refused as well.
    w.raw
        .execute(
            "UPDATE enrollments SET expires_at = expires_at + 999999",
            [],
        )
        .unwrap();
    assert!(matches!(
        w.svc.enrollment_view(&real, T0),
        Err(Error::NotFound)
    ));
}

#[test]
fn the_audit_check_notices_history_being_rewritten_in_the_tables() {
    let allowed = json!({ "type": "withdraw", "amount": "5", "asset": "USDT" });

    // A used receipt made usable again.
    let w = world("reopen");
    let token = w
        .svc
        .create_challenge(&w.project, allowed.clone(), "k1", T0)
        .unwrap()
        .receipt
        .unwrap();
    w.svc.consume_receipt(&w.project, &token, T0).unwrap();
    assert!(w.svc.audit_verify().is_ok());
    w.raw
        .execute("UPDATE receipts SET consumed_at = NULL", [])
        .unwrap();
    assert!(audit_broken(&w));

    // Past transfers deleted to win back a velocity allowance.
    let w = world("erase");
    w.svc
        .create_challenge(&w.project, allowed.clone(), "k1", T0)
        .unwrap();
    assert!(w.svc.audit_verify().is_ok());
    w.raw.execute("PRAGMA foreign_keys = OFF", []).unwrap();
    w.raw.execute("DELETE FROM receipts", []).unwrap();
    w.raw.execute("DELETE FROM challenges", []).unwrap();
    assert!(audit_broken(&w));

    // A challenge that never went through the server.
    let w = world("insert");
    w.svc
        .create_challenge(&w.project, allowed, "k1", T0)
        .unwrap();
    w.raw.execute(
        "INSERT INTO challenges (id, project, idempotency_key, action, action_hash, state, expires_at, created_at) \
         SELECT 'ch_planted', project, 'x', action, action_hash, 'allowed', expires_at, created_at FROM challenges",
        [],
    ).unwrap();
    assert!(audit_broken(&w));
}

#[test]
fn an_old_version_of_a_row_cannot_be_put_back() {
    let w = world("rollback");
    // Two of three must approve. Alice approves, bob sees fraud and refuses.
    let carol = ServerKey::generate();
    w.svc
        .add_approver(&w.project, "carol", "carol", T0)
        .unwrap();
    let carol_cred = w
        .svc
        .add_credential(
            &w.project,
            "carol",
            ApproverKind::Ed25519,
            &carol.public_hex(),
            T0,
        )
        .unwrap();
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    w.svc
        .submit_approval(&ch.id, &w.alice.1, &sign(&w, &w.alice.0, &ch.id), false, T0)
        .unwrap();
    let carol_sig = sign(&w, &carol, &ch.id);
    // The attacker saves the row while it is still pending, seal included.
    let saved: (String, Option<String>) = w
        .raw
        .query_row(
            "SELECT state, seal FROM challenges WHERE id = ?",
            [&ch.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let reject = twof_core::b64(
        &w.bob.0.sign(
            &w.svc
                .approver_view(&ch.id, T0)
                .unwrap()
                .binding
                .reject_hash(),
        ),
    );
    assert_eq!(
        w.svc
            .submit_approval(&ch.id, &w.bob.1, &reject, true, T0)
            .unwrap()
            .state,
        "rejected"
    );

    // ...and puts it back, hoping carol's approval completes the quorum.
    w.raw
        .execute(
            "UPDATE challenges SET state = ?, seal = ?, decided_at = NULL WHERE id = ?",
            rusqlite::params![saved.0, saved.1, ch.id],
        )
        .unwrap();
    assert!(matches!(
        w.svc
            .submit_approval(&ch.id, &carol_cred, &carol_sig, false, T0),
        Err(Error::Conflict(_))
    ));
    assert!(audit_broken(&w));

    // A used receipt whose mark was erased is still refused.
    let token = w
        .svc
        .create_challenge(
            &w.project,
            json!({ "type": "withdraw", "amount": "5", "asset": "USDT" }),
            "k2",
            T0,
        )
        .unwrap()
        .receipt
        .unwrap();
    w.svc.consume_receipt(&w.project, &token, T0).unwrap();
    w.raw
        .execute("UPDATE receipts SET consumed_at = NULL", [])
        .unwrap();
    assert!(matches!(
        w.svc.consume_receipt(&w.project, &token, T0),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn the_audit_check_notices_an_old_policy_being_restored() {
    let w = world("policy-rollback");
    let old: (String, Option<String>) = w
        .raw
        .query_row(
            "SELECT policy, policy_seal FROM projects WHERE id = ?",
            [&w.project],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // The owner tightens the rules: everything is refused from now on.
    w.svc
        .set_policy(&w.project, r#"{"version":1,"rules":[]}"#, T0)
        .unwrap();
    assert!(w.svc.audit_verify().is_ok());
    // The attacker restores the earlier, looser policy with its genuine seal.
    w.raw
        .execute(
            "UPDATE projects SET policy = ?, policy_seal = ? WHERE id = ?",
            rusqlite::params![old.0, old.1, w.project],
        )
        .unwrap();
    assert!(
        audit_broken(&w),
        "restoring a superseded policy is reported"
    );
    // And the server does not act on it: the log says everything is refused.
    let ch = w
        .svc
        .create_challenge(
            &w.project,
            json!({ "type": "withdraw", "amount": "5", "asset": "USDT" }),
            "k1",
            T0,
        )
        .unwrap();
    assert_eq!(ch.state, "denied");
}

#[test]
fn a_renamed_project_is_shown_by_its_id() {
    let w = world("rename");
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    assert_eq!(
        w.svc.approver_view(&ch.id, T0).unwrap().project_name,
        "exchange"
    );
    // Make a real request look like a drill.
    w.raw
        .execute(
            "UPDATE projects SET name = 'TEST ONLY - nothing here is real'",
            [],
        )
        .unwrap();
    assert_eq!(
        w.svc.approver_view(&ch.id, T0).unwrap().project_name,
        w.project
    );
}

#[test]
fn the_same_passkey_id_in_another_project_changes_nothing() {
    use twof_core::passkey::testing::SoftAuthenticator;
    use twof_core::passkey::ALG_ES256;
    let w = world("external-id");
    let other = w.svc.create_project("other", T0).unwrap();
    w.svc
        .add_approver(&other, "mallory", "mallory", T0)
        .unwrap();
    let enroll = |project: &str, approver: &str, device: &SoftAuthenticator| {
        let token = w.svc.create_enrollment(project, approver, T0).unwrap();
        let view = w.svc.enrollment_view(&token, T0).unwrap();
        let challenge = twof_core::unb64(&view.challenge).unwrap();
        let (authenticator_data, client_data_json) =
            device.register("localhost", "http://localhost:8722", &challenge);
        w.svc.complete_enrollment(
            &token,
            &twof_server::Registration {
                authenticator_data: twof_core::b64(&authenticator_data),
                client_data_json: twof_core::b64(&client_data_json),
                public_key: twof_core::b64(&device.public_key_der()),
                algorithm: ALG_ES256,
            },
            T0,
        )
    };
    // Mallory, an approver elsewhere, registers a device that claims the
    // same credential id alice's device is about to use.
    let alice_device = SoftAuthenticator::new();
    let mut squatter = SoftAuthenticator::new();
    squatter.credential_id = alice_device.credential_id.clone();
    assert!(enroll(&other, "mallory", &squatter).is_ok());
    // Alice can still register, and the same device twice is still refused.
    assert!(enroll(&w.project, "alice", &alice_device).is_ok());
    assert!(matches!(
        enroll(&w.project, "alice", &alice_device),
        Err(Error::Conflict(_))
    ));

    // Mallory's device cannot approve in alice's project under that id.
    w.svc.set_policy(&w.project, r#"{"version":1,"rules":[{"name":"p","when":{},"then":{"decision":"require","requirements":[{"count":1,"kinds":["passkey"]}]}}]}"#, T0).unwrap();
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let hash = twof_core::unb64(&w.svc.approver_view(&ch.id, T0).unwrap().binding_hash).unwrap();
    let proof = |device: &mut SoftAuthenticator| twof_server::Proof::Passkey {
        credential_id: twof_core::b64(&device.credential_id),
        assertion: device.assert("localhost", "http://localhost:8722", &hash),
    };
    assert!(matches!(
        w.svc.submit(&ch.id, &proof(&mut squatter), false, T0),
        Err(Error::Forbidden(_))
    ));
    let mut alice_device = alice_device;
    assert_eq!(
        w.svc
            .submit(&ch.id, &proof(&mut alice_device), false, T0)
            .unwrap()
            .state,
        "approved"
    );
}

#[test]
fn a_junk_row_planted_first_does_not_block_the_real_approval() {
    let w = world("squat");
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    // Before alice approves, someone plants garbage under her credential.
    w.raw
        .execute(
            "INSERT INTO approvals (challenge, approver, credential, kind, sig, created_at) \
         VALUES (?, 'alice', ?, 'ed25519', 'AAAA', 0)",
            rusqlite::params![ch.id, w.alice.1],
        )
        .unwrap();
    let after_alice = w
        .svc
        .submit_approval(&ch.id, &w.alice.1, &sign(&w, &w.alice.0, &ch.id), false, T0)
        .unwrap();
    assert_eq!(
        after_alice.approvals.len(),
        1,
        "her real signature replaced the garbage"
    );
    let done = w
        .svc
        .submit_approval(&ch.id, &w.bob.1, &sign(&w, &w.bob.0, &ch.id), false, T0)
        .unwrap();
    assert_eq!(done.state, "approved");
}

#[test]
fn the_audit_check_notices_amounts_being_lowered_to_win_back_allowance() {
    let w = world("amounts");
    w.svc
        .create_challenge(
            &w.project,
            json!({ "type": "withdraw", "amount": "9", "asset": "USDT" }),
            "k1",
            T0,
        )
        .unwrap();
    assert!(w.svc.audit_verify().is_ok());
    // The velocity limits read this column.
    w.raw
        .execute("UPDATE challenges SET amount = '0'", [])
        .unwrap();
    assert!(audit_broken(&w));
    w.raw
        .execute("UPDATE challenges SET amount = '9', asset = 'OTHER'", [])
        .unwrap();
    assert!(audit_broken(&w));
    w.raw
        .execute("UPDATE challenges SET asset = 'USDT'", [])
        .unwrap();
    assert!(w.svc.audit_verify().is_ok());
}

#[test]
fn a_revoked_credential_put_back_with_its_real_seal_stays_revoked() {
    let w = world("true-rollback");
    // The attacker copies alice's row while it is valid, seal and all.
    let saved: Option<String> = w
        .raw
        .query_row(
            "SELECT seal FROM credentials WHERE id = ?",
            [&w.alice.1],
            |r| r.get(0),
        )
        .unwrap();
    let key_row: (String, Option<String>) = {
        w.svc.create_api_key(&w.project, "bot", T0).unwrap();
        w.raw
            .query_row("SELECT id, seal FROM api_keys", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
    };
    let api_key = w.svc.create_api_key(&w.project, "second", T0).unwrap();
    // Alice's device is reported stolen and every API key is revoked.
    w.svc.revoke_credential(&w.project, &w.alice.1, T0).unwrap();
    w.svc.revoke_api_keys(&w.project, T0).unwrap();

    // Everything is put back exactly as it was, with the genuine seals.
    w.raw
        .execute(
            "UPDATE credentials SET revoked_at = NULL, seal = ? WHERE id = ?",
            rusqlite::params![saved, w.alice.1],
        )
        .unwrap();
    w.raw
        .execute(
            "UPDATE api_keys SET revoked_at = NULL, seal = ? WHERE id = ?",
            rusqlite::params![key_row.1, key_row.0],
        )
        .unwrap();
    w.raw
        .execute(
            "UPDATE api_keys SET revoked_at = NULL WHERE seal IS NULL",
            [],
        )
        .unwrap();

    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let sig = sign(&w, &w.alice.0, &ch.id);
    assert!(matches!(
        w.svc.submit_approval(&ch.id, &w.alice.1, &sig, false, T0),
        Err(Error::Forbidden(_))
    ));
    assert!(matches!(
        w.svc.authenticate(&api_key),
        Err(Error::Unauthorized)
    ));
    // Bob, who was never revoked, still works.
    assert!(w
        .svc
        .submit_approval(&ch.id, &w.bob.1, &sign(&w, &w.bob.0, &ch.id), false, T0)
        .is_ok());
}

#[test]
fn a_log_that_was_cut_or_extended_by_someone_else_stops_the_server() {
    // Cut: the newest entries are removed to hide a revocation.
    let w = world("cut");
    w.svc.revoke_credential(&w.project, &w.alice.1, T0).unwrap();
    let head: i64 = w
        .raw
        .query_row("SELECT MAX(seq) FROM audit", [], |r| r.get(0))
        .unwrap();
    w.raw
        .execute("DELETE FROM audit WHERE seq = ?", [head])
        .unwrap();
    assert!(matches!(
        w.svc.create_challenge(&w.project, big(), "k1", T0),
        Err(Error::Internal(_))
    ));
    assert!(matches!(
        w.svc.create_api_key(&w.project, "x", T0),
        Err(Error::Internal(_))
    ));

    // Extended: an entry nobody signed is appended.
    let w = world("extend");
    let (seq, hash, sig): (i64, String, String) = w
        .raw
        .query_row(
            "SELECT seq, hash, sig FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let forged = twof_core::audit::next_entry(Some((seq as u64, &hash)), T0, "credential.added",
        json!({ "credential": "cr_evil", "project": w.project, "approver": "alice", "kind": "ed25519", "public_key": "00" })).unwrap();
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
    assert!(matches!(
        w.svc.create_challenge(&w.project, big(), "k1", T0),
        Err(Error::Internal(_))
    ));
    assert!(audit_broken(&w));
}

#[test]
fn a_restarted_server_rebuilds_what_is_in_force_from_the_log() {
    let w = world("restart");
    let api_key = w.svc.create_api_key(&w.project, "bot", T0).unwrap();
    w.svc.revoke_credential(&w.project, &w.bob.1, T0).unwrap();
    let ch = w.svc.create_challenge(&w.project, big(), "k1", T0).unwrap();
    let sig_alice = sign(&w, &w.alice.0, &ch.id);
    let sig_bob = sign(&w, &w.bob.0, &ch.id);
    w.svc.checkpoint(T0).unwrap();
    w.svc
        .create_challenge(
            &w.project,
            json!({ "type": "withdraw", "amount": "5", "asset": "USDT" }),
            "k2",
            T0,
        )
        .unwrap();

    // A second process on the same file, with the same key: a restart.
    let again = Service::open(
        &w.path,
        ServerKey::from_seed_hex(&w.svc.key().seed_hex()).unwrap(),
        Config::default(),
    )
    .unwrap();
    assert_eq!(again.authenticate(&api_key).unwrap(), w.project);
    assert!(matches!(
        again.submit_approval(&ch.id, &w.bob.1, &sig_bob, false, T0),
        Err(Error::Forbidden(_))
    ));
    assert_eq!(
        again
            .submit_approval(&ch.id, &w.alice.1, &sig_alice, false, T0)
            .unwrap()
            .approvals
            .len(),
        1
    );
    assert!(again.audit_verify().is_ok());
    // The first process picks up what the second one wrote.
    assert_eq!(
        w.svc
            .get_challenge(&w.project, &ch.id, T0)
            .unwrap()
            .approvals
            .len(),
        1
    );
    assert_eq!(w.svc.authenticate(&api_key).unwrap(), w.project);

    // A log shorter than a checkpoint it holds is refused at start.
    let cut: i64 = w
        .raw
        .query_row("SELECT seq FROM checkpoints", [], |r| r.get(0))
        .unwrap();
    w.raw
        .execute("DELETE FROM audit WHERE seq >= ?", [cut])
        .unwrap();
    let third = Service::open(
        &w.path,
        ServerKey::from_seed_hex(&w.svc.key().seed_hex()).unwrap(),
        Config::default(),
    )
    .unwrap();
    assert!(matches!(
        third.authenticate(&api_key),
        Err(Error::Internal(_))
    ));
}
