//! Notifications and the independent co-signer.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use twof_core::keys::ServerKey;
use twof_core::{receipt, webhook, Action, ApproverKind, Policy};
use twof_server::cosigner::Cosigner;
use twof_server::service::OUTBOX_MAX_ATTEMPTS;
use twof_server::{Config, Error, Service};

const T0: u64 = 1_800_000_000;

/// The server asks for a person and the co-signer on every withdraw.
const SERVER_POLICY: &str = r#"{ "version": 1, "rules": [
    { "name": "person and vault", "when": { "type": ["withdraw"] },
      "then": { "decision": "require", "requirements": [
          { "count": 1, "kinds": ["ed25519"] }, { "count": 1, "kinds": ["cosigner"] } ] } } ] }"#;

/// The co-signer has its own, stricter view of the world.
const VAULT_POLICY: &str = r#"{ "version": 1, "lists": { "known": ["0xaaa"] }, "rules": [
    { "name": "blocked", "when": { "destination_in": ["known"], "amount_min": "1000000" }, "then": { "decision": "deny" } },
    { "name": "known up to 5000", "when": { "asset": ["USDT"], "destination_in": ["known"], "amount_max": "5000" }, "then": { "decision": "allow" } },
    { "name": "unsure", "when": { "asset": ["BTC"] }, "then": { "decision": "require", "requirements": [ { "count": 1 } ] } } ] }"#;

struct World {
    svc: Service,
    project: String,
    alice: (ServerKey, String),
    vault: Cosigner,
}

fn world() -> World {
    let svc = Service::open_in_memory(ServerKey::generate(), Config::default()).unwrap();
    let project = svc.create_project("exchange", T0).unwrap();
    svc.set_policy(&project, SERVER_POLICY, T0).unwrap();
    svc.set_webhook(&project, Some("http://vault.internal:8723/webhook"), T0)
        .unwrap();
    svc.set_telegram(&project, Some("-100123"), T0).unwrap();

    let alice_key = ServerKey::generate();
    svc.add_approver(&project, "alice", "Alice", T0).unwrap();
    let alice_cred = svc
        .add_credential(
            &project,
            "alice",
            ApproverKind::Ed25519,
            &alice_key.public_hex(),
            T0,
        )
        .unwrap();

    let vault_key = ServerKey::generate();
    svc.add_approver(&project, "vault", "Vault", T0).unwrap();
    let vault_cred = svc
        .add_credential(
            &project,
            "vault",
            ApproverKind::Cosigner,
            &vault_key.public_hex(),
            T0,
        )
        .unwrap();
    let vault = Cosigner::new(
        vault_key,
        vault_cred,
        Policy::parse(VAULT_POLICY).unwrap(),
        "http://unused".into(),
        svc.key().public(),
    );
    World {
        svc,
        project,
        alice: (alice_key, alice_cred),
        vault,
    }
}

fn withdraw(amount: &str, asset: &str, destination: &str) -> Value {
    json!({ "type": "withdraw", "amount": amount, "asset": asset, "destination": destination })
}

/// Takes the queued webhook for the newest event and signs it as the server would.
fn next_webhook(w: &World) -> (String, String) {
    let items = w.svc.outbox_due(T0 + 10, 100).unwrap();
    let item = items
        .iter()
        .rev()
        .find(|i| i.kind == "webhook")
        .expect("a webhook is queued");
    for i in &items {
        w.svc.outbox_result(i.id, true, T0).unwrap();
    }
    (
        item.body.clone(),
        webhook::sign(w.svc.key(), item.body.as_bytes()),
    )
}

#[test]
fn pending_challenges_queue_a_signed_webhook_and_a_telegram_message() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("100", "USDT", "0xaaa"), "k1", T0)
        .unwrap();
    let items = w.svc.outbox_due(T0, 100).unwrap();
    assert_eq!(
        items.iter().map(|i| i.kind.as_str()).collect::<Vec<_>>(),
        ["telegram", "webhook"]
    );

    let telegram = &items[0];
    assert_eq!(telegram.target, "-100123");
    assert!(
        telegram.body.contains("Amount: 100 USDT") && telegram.body.contains("Destination: 0xaaa")
    );
    assert!(telegram.body.contains(&format!("/approve/{}", ch.id)));

    let hook = &items[1];
    let event: Value = serde_json::from_str(&hook.body).unwrap();
    assert_eq!(event["event"], "challenge.pending");
    assert_eq!(event["data"]["action"]["amount"], "100");
    // Receipts never travel in notifications.
    assert!(!hook.body.contains("receipt"));

    // Allowed and denied challenges do not notify anyone.
    let quiet = w
        .svc
        .create_challenge(&w.project, json!({ "type": "trade" }), "k2", T0)
        .unwrap();
    assert_eq!(quiet.state, "denied");
    assert_eq!(w.svc.outbox_due(T0, 100).unwrap().len(), 2);
}

#[test]
fn failed_deliveries_back_off_and_eventually_stop() {
    let w = world();
    w.svc.set_telegram(&w.project, None, T0).unwrap();
    w.svc
        .create_challenge(&w.project, withdraw("100", "USDT", "0xaaa"), "k1", T0)
        .unwrap();
    let id = w.svc.outbox_due(T0, 10).unwrap()[0].id;

    w.svc.outbox_result(id, false, T0).unwrap();
    assert!(
        w.svc.outbox_due(T0, 10).unwrap().is_empty(),
        "retry is delayed"
    );
    assert_eq!(w.svc.outbox_due(T0 + 3600, 10).unwrap().len(), 1);
    for _ in 1..OUTBOX_MAX_ATTEMPTS {
        w.svc.outbox_result(id, false, T0).unwrap();
    }
    assert!(
        w.svc.outbox_due(T0 + 10_000_000, 10).unwrap().is_empty(),
        "gave up"
    );

    assert!(matches!(
        w.svc.set_webhook(&w.project, Some("ftp://x"), T0),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        w.svc.set_webhook(&w.project, Some("https://x y"), T0),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn person_plus_cosigner_approve_and_the_client_can_pin_both() {
    let w = world();
    let action = withdraw("100", "USDT", "0xaaa");
    let ch = w
        .svc
        .create_challenge(&w.project, action.clone(), "k1", T0)
        .unwrap();
    let (body, sig) = next_webhook(&w);

    let verdict = w
        .vault
        .decide(&body, &sig, T0)
        .unwrap()
        .expect("vault signs");
    assert!(!verdict.reject);
    let after_vault = w
        .svc
        .submit_approval(
            &verdict.challenge,
            &w.vault.credential,
            &verdict.signature,
            false,
            T0,
        )
        .unwrap();
    assert_eq!(
        after_vault.state, "pending",
        "the vault alone is not enough"
    );

    let hash = w.svc.approver_view(&ch.id, T0).unwrap().binding.hash();
    let done = w
        .svc
        .submit_approval(
            &ch.id,
            &w.alice.1,
            &twof_core::b64(&w.alice.0.sign(&hash)),
            false,
            T0,
        )
        .unwrap();
    assert_eq!(done.state, "approved");

    let server_key = w.svc.key();
    let lookup = |kid: &str| (kid == server_key.kid()).then(|| server_key.public());
    let payload = receipt::verify(
        &done.receipt.unwrap(),
        &lookup,
        &Action::from_value(action).unwrap(),
        T0,
    )
    .unwrap();
    let pinned = BTreeMap::from([
        ("alice".to_string(), w.alice.0.public()),
        ("vault".to_string(), w.vault.key.public()),
    ]);
    assert_eq!(payload.pinned_approvals(&pinned).len(), 2);
}

#[test]
fn cosigner_vetoes_what_its_own_policy_denies() {
    let w = world();
    let ch = w
        .svc
        .create_challenge(&w.project, withdraw("2000000", "USDT", "0xaaa"), "k1", T0)
        .unwrap();
    let (body, sig) = next_webhook(&w);
    let verdict = w
        .vault
        .decide(&body, &sig, T0)
        .unwrap()
        .expect("vault vetoes");
    assert!(verdict.reject);
    let after = w
        .svc
        .submit_approval(&ch.id, &w.vault.credential, &verdict.signature, true, T0)
        .unwrap();
    assert_eq!(after.state, "rejected");
}

#[test]
fn cosigner_abstains_when_unsure_or_when_nothing_matches() {
    let w = world();
    for (key, action) in [
        ("k1", withdraw("1", "BTC", "0xzzz")),
        ("k2", withdraw("9000", "USDT", "0xaaa")),
    ] {
        w.svc.create_challenge(&w.project, action, key, T0).unwrap();
        let (body, sig) = next_webhook(&w);
        match key {
            "k1" => assert_eq!(w.vault.decide(&body, &sig, T0).unwrap(), None),
            // No rule matches: the vault's own default is deny, which is a veto.
            _ => assert!(w.vault.decide(&body, &sig, T0).unwrap().unwrap().reject),
        }
    }
}

#[test]
fn cosigner_refuses_forged_stale_or_inconsistent_webhooks() {
    let w = world();
    w.svc
        .create_challenge(&w.project, withdraw("100", "USDT", "0xaaa"), "k1", T0)
        .unwrap();
    let (body, sig) = next_webhook(&w);
    assert!(w.vault.decide(&body, &sig, T0).unwrap().is_some());

    // Signed by someone who is not the server.
    let attacker = ServerKey::generate();
    assert!(matches!(
        w.vault
            .decide(&body, &webhook::sign(&attacker, body.as_bytes()), T0),
        Err(Error::Forbidden(_))
    ));
    // Body changed after signing.
    assert!(matches!(
        w.vault.decide(&body.replace("0xaaa", "0xbad"), &sig, T0),
        Err(Error::Forbidden(_))
    ));
    // Replayed later.
    assert!(matches!(
        w.vault.decide(&body, &sig, T0 + webhook::MAX_AGE + 1),
        Err(Error::Invalid(_))
    ));

    // A compromised server signs a webhook that shows a harmless action but
    // carries the binding of a dangerous one. The co-signer must not sign it.
    let evil = w
        .svc
        .create_challenge(&w.project, withdraw("4000", "USDT", "0xevil"), "k2", T0)
        .unwrap();
    let (evil_body, _) = next_webhook(&w);
    let mut event: Value = serde_json::from_str(&body).unwrap();
    let evil_event: Value = serde_json::from_str(&evil_body).unwrap();
    event["data"]["binding"] = evil_event["data"]["binding"].clone();
    let mixed = twof_core::canonical::to_canonical(&event).unwrap();
    let mixed_sig = webhook::sign(w.svc.key(), mixed.as_bytes());
    assert!(matches!(
        w.vault.decide(&mixed, &mixed_sig, T0),
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        w.svc.get_challenge(&w.project, &evil.id, T0).unwrap().state,
        "pending"
    );
}

#[test]
fn cosigner_keeps_its_own_running_total() {
    let w = world();
    let policy = r#"{ "version": 1, "rules": [
        { "name": "capped", "when": { "asset": ["USDT"], "amount_max": "3000",
                                      "velocity": { "window_secs": 3600, "max_total": "6000" } },
          "then": { "decision": "allow" } } ] }"#;
    let vault = Cosigner::new(
        ServerKey::generate(),
        "cr_x".into(),
        Policy::parse(policy).unwrap(),
        "http://unused".into(),
        w.svc.key().public(),
    );
    let mut deliveries = Vec::new();
    for key in ["k1", "k2", "k3"] {
        w.svc
            .create_challenge(&w.project, withdraw("2500", "USDT", "0xaaa"), key, T0)
            .unwrap();
        deliveries.push(next_webhook(&w));
    }
    // A compromised server asking for many approvals that each look small.
    let decide = |i: usize| {
        vault
            .decide(&deliveries[i].0, &deliveries[i].1, T0)
            .unwrap()
            .unwrap()
    };
    assert!(!decide(0).reject);
    assert!(!decide(1).reject);
    assert!(
        decide(2).reject,
        "2500 + 2500 + 2500 is over the co-signer's own 6000"
    );
    // Hearing about the same challenge again does not use the budget twice.
    assert!(!decide(0).reject);
    assert!(!decide(1).reject);
    assert!(decide(2).reject);
}

#[test]
fn notifications_planted_in_the_database_are_not_sent_in_the_servers_name() {
    let path = {
        let mut p = std::env::temp_dir();
        p.push(format!("twof-outbox-{}.db", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", p.display()));
        }
        p
    };
    let svc = Service::open(&path, ServerKey::generate(), Config::default()).unwrap();
    let project = svc.create_project("exchange", T0).unwrap();
    svc.set_policy(&project, SERVER_POLICY, T0).unwrap();
    svc.set_webhook(&project, Some("http://vault.internal:8723/webhook"), T0)
        .unwrap();
    svc.create_challenge(&project, withdraw("100", "USDT", "0xaaa"), "k1", T0)
        .unwrap();
    let real = svc.outbox_due(T0, 10).unwrap();
    assert_eq!(real.len(), 1);
    assert!(svc.outbox_authentic(&real[0]));

    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.busy_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // A forged event, with the seal copied from the real one.
    raw.execute(
        "INSERT INTO outbox (project, kind, target, body, seal, next_at) \
         SELECT project, 'webhook', target, '{\"event\":\"challenge.approved\"}', seal, 0 FROM outbox",
        [],
    )
    .unwrap();
    // The real event, redirected to the attacker.
    raw.execute(
        "UPDATE outbox SET target = 'http://evil.example/collect' WHERE id = ?",
        [real[0].id],
    )
    .unwrap();
    let items = svc.outbox_due(T0, 10).unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| !svc.outbox_authentic(item)));

    // Redirecting future notifications by editing the channel is ignored too:
    // nothing is queued for a destination this server did not set.
    raw.execute("DELETE FROM outbox", []).unwrap();
    raw.execute(
        "UPDATE channels SET webhook_url = 'http://evil.example/collect'",
        [],
    )
    .unwrap();
    svc.create_challenge(&project, withdraw("100", "USDT", "0xaaa"), "k2", T0)
        .unwrap();
    assert!(svc.outbox_due(T0, 10).unwrap().is_empty());
    drop(svc);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
